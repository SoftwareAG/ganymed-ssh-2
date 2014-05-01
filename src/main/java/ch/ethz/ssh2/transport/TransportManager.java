/*
 * Copyright (c) 2006-2013 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */

package ch.ethz.ssh2.transport;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.ConnectionMonitor;
import ch.ethz.ssh2.DHGexParameters;
import ch.ethz.ssh2.PacketTypeException;
import ch.ethz.ssh2.compression.Compressor;
import ch.ethz.ssh2.crypto.CryptoWishList;
import ch.ethz.ssh2.crypto.cipher.BlockCipher;
import ch.ethz.ssh2.crypto.digest.MAC;
import ch.ethz.ssh2.log.Logger;
import ch.ethz.ssh2.packets.PacketDisconnect;
import ch.ethz.ssh2.packets.Packets;
import ch.ethz.ssh2.packets.TypesReader;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.RSAPrivateKey;

/**
 * Yes, the "standard" is a big mess. On one side, the say that arbitrary channel
 * packets are allowed during kex exchange, on the other side we need to blindly
 * ignore the next _packet_ if the KEX guess was wrong. Where do we know from that
 * the next packet is not a channel data packet? Yes, we could check if it is in
 * the KEX range. But the standard says nothing about this. The OpenSSH guys
 * block local "normal" traffic during KEX. That's fine - however, they assume
 * that the other side is doing the same. During re-key, if they receive traffic
 * other than KEX, they become horribly irritated and kill the connection. Since
 * we are very likely going to communicate with OpenSSH servers, we have to play
 * the same game - even though we could do better.
 *
 * @author Christian Plattner
 * @version $Id$
 */
public abstract class TransportManager {
    private static final Logger log = Logger.getLogger(TransportManager.class);

    private static final class HandlerEntry {
        MessageHandler mh;
        int low;
        int high;
    }

    /**
     * Advertised maximum SSH packet size that the other side can send to us.
     */
    public static final int MAX_PACKET_SIZE = 64 * 1024;

    private final List<AsynchronousEntry> asynchronousQueue
            = new ArrayList<AsynchronousEntry>();

    private Thread asynchronousThread = null;
    private boolean asynchronousPending = false;

    private Socket sock;

    protected TransportManager(final Socket sock) {
        this.sock = sock;
    }

    private static final class AsynchronousEntry {
        public byte[] message;

        public AsynchronousEntry(byte[] message) {
            this.message = message;
        }
    }

    private final class AsynchronousWorker implements Runnable {
        @Override
        public void run() {
            while(true) {
                final AsynchronousEntry item;
                synchronized(asynchronousQueue) {
                    if(asynchronousQueue.size() == 0) {
                        // Only now we may reset the flag, since we are sure that all queued items
                        // have been sent (there is a slight delay between de-queuing and sending,
                        // this is why we need this flag! See code below. Sending takes place outside
                        // of this lock, this is why a test for size()==0 (from another thread) does not ensure
                        // that all messages have been sent.

                        asynchronousPending = false;

                        // Notify any senders that they can proceed, all async messages have been delivered

                        asynchronousQueue.notifyAll();

                        // After the queue is empty for about 2 seconds, stop this thread
                        try {
                            asynchronousQueue.wait(2000);
                        }
                        catch(InterruptedException ignore) {
                            //
                        }
                        if(asynchronousQueue.size() == 0) {
                            asynchronousThread = null;
                            return;
                        }
                    }
                    item = asynchronousQueue.remove(0);
                }
                try {
                    sendMessageImmediate(item.message);
                }
                catch(IOException e) {
                    // There is no point in handling it - it simply means that the connection has a problem and we should stop
                    // sending asynchronously messages. We do not need to signal that we have exited (asynchronousThread = null):
                    // further messages in the queue cannot be sent by this or any other thread.
                    // Other threads will sooner or later (when receiving or sending the next message) get the
                    // same IOException and get to the same conclusion.
                    log.warning(e.getMessage());
                    return;
                }
            }
        }
    }

    private final Object connectionSemaphore = new Object();

    private boolean flagKexOngoing;

    private boolean connectionClosed;
    private IOException reasonClosedCause;

    private TransportConnection tc;
    private KexManager km;

    private final List<HandlerEntry> messageHandlers
            = new ArrayList<HandlerEntry>();

    private List<ConnectionMonitor> connectionMonitors
            = new ArrayList<ConnectionMonitor>();

    protected void init(TransportConnection tc, KexManager km) {
        this.tc = tc;
        this.km = km;
    }

    public int getPacketOverheadEstimate() {
        return tc.getPacketOverheadEstimate();
    }

    public ConnectionInfo getConnectionInfo(int kexNumber) throws IOException {
        return km.getOrWaitForConnectionInfo(kexNumber);
    }

    public IOException getReasonClosedCause() {
        synchronized(connectionSemaphore) {
            return reasonClosedCause;
        }
    }

    public byte[] getSessionIdentifier() {
        return km.sessionId;
    }

    public void close() {
        // It is safe now to acquire the semaphore.
        synchronized(connectionSemaphore) {
            if(!connectionClosed) {
                try {
                    tc.sendMessage(new PacketDisconnect(
                            PacketDisconnect.Reason.SSH_DISCONNECT_BY_APPLICATION, "").getPayload());
                }
                catch(IOException ignore) {
                    //
                }
                try {
                    sock.close();
                }
                catch(IOException ignore) {
                    //
                }
                connectionClosed = true;
                synchronized(this) {
                    for(ConnectionMonitor cmon : connectionMonitors) {
                        cmon.connectionLost(reasonClosedCause);
                    }
                }
            }
            connectionSemaphore.notifyAll();
        }
    }

    public void close(IOException cause) {
        // Do not acquire the semaphore, perhaps somebody is inside (and waits until
        // the remote side is ready to accept new data
        try {
            sock.close();
        }
        catch(IOException ignore) {
        }
        // It is safe now to acquire the semaphore.
        synchronized(connectionSemaphore) {
            connectionClosed = true;
            reasonClosedCause = cause;
            connectionSemaphore.notifyAll();
        }
        synchronized(this) {
            for(ConnectionMonitor cmon : connectionMonitors) {
                cmon.connectionLost(reasonClosedCause);
            }
        }
    }

    protected void startReceiver() throws IOException {
        final Thread receiveThread = new Thread(new Runnable() {
            public void run() {
                try {
                    receiveLoop();
                    // Can only exit with exception
                }
                catch(IOException e) {
                    close(e);
                    log.warning(e.getMessage());
                    // Tell all handlers that it is time to say goodbye
                    if(km != null) {
                        km.handleFailure(e);
                    }
                    for(HandlerEntry he : messageHandlers) {
                        he.mh.handleFailure(e);
                    }
                }
                if(log.isDebugEnabled()) {
                    log.debug("Receive thread: back from receiveLoop");
                }
            }
        });
        receiveThread.setName("Transport Manager");
        receiveThread.setDaemon(true);
        receiveThread.start();
    }

    public void registerMessageHandler(MessageHandler mh, int low, int high) {
        HandlerEntry he = new HandlerEntry();
        he.mh = mh;
        he.low = low;
        he.high = high;

        synchronized(messageHandlers) {
            messageHandlers.add(he);
        }
    }

    public void removeMessageHandler(MessageHandler mh, int low, int high) {
        synchronized(messageHandlers) {
            for(int i = 0; i < messageHandlers.size(); i++) {
                HandlerEntry he = messageHandlers.get(i);
                if((he.mh == mh) && (he.low == low) && (he.high == high)) {
                    messageHandlers.remove(i);
                    break;
                }
            }
        }
    }

    public void sendKexMessage(byte[] msg) throws IOException {
        synchronized(connectionSemaphore) {
            if(connectionClosed) {
                throw reasonClosedCause;
            }
            flagKexOngoing = true;
            try {
                tc.sendMessage(msg);
            }
            catch(IOException e) {
                close(e);
                throw e;
            }
        }
    }

    public void kexFinished() throws IOException {
        synchronized(connectionSemaphore) {
            flagKexOngoing = false;
            connectionSemaphore.notifyAll();
        }
    }

    /**
     * @param cwl   Crypto wishlist
     * @param dhgex Diffie-hellman group exchange
     * @param dsa   may be null if this is a client connection
     * @param rsa   may be null if this is a client connection
     * @throws IOException
     */
    public void forceKeyExchange(CryptoWishList cwl, DHGexParameters dhgex, DSAPrivateKey dsa, RSAPrivateKey rsa)
            throws IOException {
        synchronized(connectionSemaphore) {
            if(connectionClosed) {
                // Inform the caller that there is no point in triggering a new kex
                throw reasonClosedCause;
            }
        }
        km.initiateKEX(cwl, dhgex, dsa, rsa);
    }

    public void changeRecvCipher(BlockCipher bc, MAC mac) {
        tc.changeRecvCipher(bc, mac);
    }

    public void changeSendCipher(BlockCipher bc, MAC mac) {
        tc.changeSendCipher(bc, mac);
    }

    public void changeRecvCompression(Compressor comp) {
        tc.changeRecvCompression(comp);
    }

    public void changeSendCompression(Compressor comp) {
        tc.changeSendCompression(comp);
    }

    public void sendAsynchronousMessage(byte[] msg) throws IOException {
        synchronized(asynchronousQueue) {
            asynchronousQueue.add(new AsynchronousEntry(msg));
            asynchronousPending = true;

			/* This limit should be flexible enough. We need this, otherwise the peer
             * can flood us with global requests (and other stuff where we have to reply
			 * with an asynchronous message) and (if the server just sends data and does not
			 * read what we send) this will probably put us in a low memory situation
			 * (our send queue would grow and grow and...) */

            if(asynchronousQueue.size() > 100) {
                throw new IOException("The peer is not consuming our asynchronous replies.");
            }

            // Check if we have an asynchronous sending thread
            if(asynchronousThread == null) {
                asynchronousThread = new Thread(new AsynchronousWorker());
                asynchronousThread.setDaemon(true);
                asynchronousThread.start();
                // The thread will stop after 2 seconds of inactivity (i.e., empty queue)
            }
            asynchronousQueue.notifyAll();
        }
    }

    public void setConnectionMonitors(List<ConnectionMonitor> monitors) {
        synchronized(this) {
            connectionMonitors = new ArrayList<ConnectionMonitor>();
            connectionMonitors.addAll(monitors);
        }
    }

    /**
     * Send a message but ensure that all queued messages are being sent first.
     *
     * @param msg Message
     * @throws IOException
     */
    public void sendMessage(byte[] msg) throws IOException {
        synchronized(asynchronousQueue) {
            while(asynchronousPending) {
                try {
                    asynchronousQueue.wait();
                }
                catch(InterruptedException e) {
                    throw new InterruptedIOException(e.getMessage());
                }
            }
        }
        sendMessageImmediate(msg);
    }

    /**
     * Send message, ignore queued async messages that have not been delivered yet.
     * Will be called directly from the asynchronousThread thread.
     *
     * @param msg Message
     * @throws IOException
     */
    public void sendMessageImmediate(byte[] msg) throws IOException {
        synchronized(connectionSemaphore) {
            while(true) {
                if(connectionClosed) {
                    throw reasonClosedCause;
                }
                if(!flagKexOngoing) {
                    break;
                }
                try {
                    connectionSemaphore.wait();
                }
                catch(InterruptedException e) {
                    throw new InterruptedIOException(e.getMessage());
                }
            }

            try {
                tc.sendMessage(msg);
            }
            catch(IOException e) {
                close(e);
                throw e;
            }
        }
    }

    private void receiveLoop() throws IOException {
        while(true) {
            final byte[] buffer = new byte[MAX_PACKET_SIZE];
            final int length = tc.receiveMessage(buffer, 0, buffer.length);
            final byte[] packet = new byte[length];
            System.arraycopy(buffer, 0, packet, 0, length);
            final int type = packet[0] & 0xff;
            switch(type) {
                case Packets.SSH_MSG_IGNORE:
                    break;
                case Packets.SSH_MSG_DEBUG: {
                    TypesReader tr = new TypesReader(packet);
                    tr.readByte();
                    // always_display
                    tr.readBoolean();
                    String message = tr.readString();
                    if(log.isDebugEnabled()) {
                        log.debug(String.format("Debug message from remote: '%s'", message));
                    }
                    break;
                }
                case Packets.SSH_MSG_UNIMPLEMENTED:
                    throw new PacketTypeException(type);
                case Packets.SSH_MSG_DISCONNECT: {
                    final PacketDisconnect disconnect = new PacketDisconnect(packet);
                    throw new DisconnectException(disconnect.getReason(), disconnect.getMessage());
                }
                case Packets.SSH_MSG_KEXINIT:
                case Packets.SSH_MSG_NEWKEYS:
                case Packets.SSH_MSG_KEXDH_INIT:
                case Packets.SSH_MSG_KEXDH_REPLY:
                case Packets.SSH_MSG_KEX_DH_GEX_REQUEST:
                case Packets.SSH_MSG_KEX_DH_GEX_INIT:
                case Packets.SSH_MSG_KEX_DH_GEX_REPLY:
                    // Is it a KEX Packet
                    km.handleMessage(packet);
                    break;
                case Packets.SSH_MSG_USERAUTH_SUCCESS:
                    tc.startCompression();
                    // Continue with message handlers
                default:
                    boolean handled = false;
                    for(HandlerEntry handler : messageHandlers) {
                        if((handler.low <= type) && (type <= handler.high)) {
                            handler.mh.handleMessage(packet);
                            handled = true;
                            break;
                        }
                    }
                    if(!handled) {
                        throw new PacketTypeException(type);
                    }
                    break;
            }
            if(log.isDebugEnabled()) {
                log.debug(String.format("Handled packet %d", type));
            }
        }
    }
}
