/*
 * Copyright (c) 2006-2013 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */

package ch.ethz.ssh2.transport;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;

import ch.ethz.ssh2.ConnectionInfo;
import ch.ethz.ssh2.ConnectionMonitor;
import ch.ethz.ssh2.DHGexParameters;
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

/*
 * Yes, the "standard" is a big mess. On one side, the say that arbitary channel
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
 * btw: having stdout and stderr on the same channel, with a shared window, is
 * also a VERY good idea... =(
 */

/**
 * TransportManager.
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

    private final List<AsynchronousEntry> asynchronousQueue = new ArrayList<AsynchronousEntry>();
    private Thread asynchronousThread = null;
    private boolean asynchronousPending = false;

    private Socket sock;

    protected TransportManager(final Socket sock) {
        this.sock = sock;
    }

    private static final class AsynchronousEntry {
        public byte[] msg;
        public Runnable run;

        public AsynchronousEntry(byte[] msg, Runnable run) {
            this.msg = msg;
            this.run = run;
        }
    }

    private final class AsynchronousWorker extends Thread {
        @Override
        public void run() {
            while(true) {
                AsynchronousEntry item;

                synchronized(asynchronousQueue) {
                    if(asynchronousQueue.size() == 0) {
                        /* Only now we may reset the flag, since we are sure that all queued items
                         * have been sent (there is a slight delay between de-queuing and sending,
						 * this is why we need this flag! See code below. Sending takes place outside
						 * of this lock, this is why a test for size()==0 (from another thread) does not ensure
						 * that all messages have been sent.
						 */

                        asynchronousPending = false;

						/* Notify any senders that they can proceed, all async messages have been delivered */

                        asynchronousQueue.notifyAll();

						/* After the queue is empty for about 2 seconds, stop this thread */

                        try {
                            asynchronousQueue.wait(2000);
                        }
                        catch(InterruptedException ignore) {
                        }

                        if(asynchronousQueue.size() == 0) {
                            asynchronousThread = null;
                            return;
                        }
                    }

                    item = asynchronousQueue.remove(0);
                }

				/* The following invocation may throw an IOException.
                 * There is no point in handling it - it simply means
				 * that the connection has a problem and we should stop
				 * sending asynchronously messages. We do not need to signal that
				 * we have exited (asynchronousThread = null): further
				 * messages in the queue cannot be sent by this or any
				 * other thread.
				 * Other threads will sooner or later (when receiving or
				 * sending the next message) get the same IOException and
				 * get to the same conclusion.
				 */

                try {
                    sendMessageImmediate(item.msg);
                }
                catch(IOException e) {
                    return;
                }

                if(item.run != null) {
                    try {
                        item.run.run();
                    }
                    catch(Exception ignore) {
                    }

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

    private final List<HandlerEntry> messageHandlers = new ArrayList<HandlerEntry>();

    private Thread receiveThread;

    private List<ConnectionMonitor> connectionMonitors = new ArrayList<ConnectionMonitor>();

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
                    byte[] msg = new PacketDisconnect(Packets.SSH_DISCONNECT_BY_APPLICATION, "", "").getPayload();
                    if(tc != null) {
                        tc.sendMessage(msg);
                    }
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
        receiveThread = new Thread(new Runnable() {
            public void run() {
                try {
                    receiveLoop();
                    // Can only exit with exception
                }
                catch(IOException e) {
                    close(e);
                    log.warning("Receive thread: error in receiveLoop: " + e.getMessage());
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
     * @param cwl
     * @param dhgex
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

    public void startCompression() {
        tc.startCompression();
    }

    public void sendAsynchronousMessage(byte[] msg) throws IOException {
        sendAsynchronousMessage(msg, null);
    }

    public void sendAsynchronousMessage(byte[] msg, Runnable run) throws IOException {
        synchronized(asynchronousQueue) {
            asynchronousQueue.add(new AsynchronousEntry(msg, run));
            asynchronousPending = true;

			/* This limit should be flexible enough. We need this, otherwise the peer
             * can flood us with global requests (and other stuff where we have to reply
			 * with an asynchronous message) and (if the server just sends data and does not
			 * read what we send) this will probably put us in a low memory situation
			 * (our send queue would grow and grow and...) */

            if(asynchronousQueue.size() > 100) {
                throw new IOException("Error: the peer is not consuming our asynchronous replies.");
            }

			/* Check if we have an asynchronous sending thread */

            if(asynchronousThread == null) {
                asynchronousThread = new AsynchronousWorker();
                asynchronousThread.setDaemon(true);
                asynchronousThread.start();

				/* The thread will stop after 2 seconds of inactivity (i.e., empty queue) */
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
     * True if no response message expected.
     */
    private boolean idle;

    /**
     * Send a message but ensure that all queued messages are being sent first.
     *
     * @param msg
     * @throws IOException
     */
    public void sendMessage(byte[] msg) throws IOException {
        synchronized(asynchronousQueue) {
            while(asynchronousPending) {
                try {
                    asynchronousQueue.wait(1000);
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
     * @param msg
     * @throws IOException
     */
    public void sendMessageImmediate(byte[] msg) throws IOException {
        if(Thread.currentThread() == receiveThread) {
            throw new IOException("Assertion error: sendMessage may never be invoked by the receiver thread!");
        }
        synchronized(connectionSemaphore) {
            while(true) {
                if(connectionClosed) {
                    throw reasonClosedCause;
                }

                if(flagKexOngoing == false) {
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
                idle = false;
            }
            catch(IOException e) {
                close(e);
                throw e;
            }
        }
    }

    private void receiveLoop() throws IOException {
        byte[] msg = new byte[MAX_PACKET_SIZE];

        while(true) {
            int msglen;
            try {
                msglen = tc.receiveMessage(msg, 0, msg.length);
            }
            catch(SocketTimeoutException e) {
                // Timeout in read
                if(idle) {
                    log.debug("Ignoring socket timeout");
                    continue;
                }
                throw e;
            }
            idle = true;

            int type = msg[0] & 0xff;

            if(type == Packets.SSH_MSG_IGNORE) {
                continue;
            }

            if(type == Packets.SSH_MSG_DEBUG) {
                if(log.isDebugEnabled()) {
                    TypesReader tr = new TypesReader(msg, 0, msglen);
                    tr.readByte();
                    tr.readBoolean();
                    StringBuilder debugMessageBuffer = new StringBuilder();
                    debugMessageBuffer.append(tr.readString("UTF-8"));

                    for(int i = 0; i < debugMessageBuffer.length(); i++) {
                        char c = debugMessageBuffer.charAt(i);

                        if((c >= 32) && (c <= 126)) {
                            continue;
                        }
                        debugMessageBuffer.setCharAt(i, '\uFFFD');
                    }

                    log.debug("DEBUG Message from remote: '" + debugMessageBuffer.toString() + "'");
                }
                continue;
            }

            if(type == Packets.SSH_MSG_UNIMPLEMENTED) {
                throw new IOException("Peer sent UNIMPLEMENTED message, that should not happen.");
            }

            if(type == Packets.SSH_MSG_DISCONNECT) {
                TypesReader tr = new TypesReader(msg, 0, msglen);
                tr.readByte();
                int reason_code = tr.readUINT32();
                StringBuilder reasonBuffer = new StringBuilder();
                reasonBuffer.append(tr.readString("UTF-8"));

				/*
                 * Do not get fooled by servers that send abnormal long error
				 * messages
				 */

                if(reasonBuffer.length() > 255) {
                    reasonBuffer.setLength(255);
                    reasonBuffer.setCharAt(254, '.');
                    reasonBuffer.setCharAt(253, '.');
                    reasonBuffer.setCharAt(252, '.');
                }

				/*
                 * Also, check that the server did not send characters that may
				 * screw up the receiver -> restrict to reasonable US-ASCII
				 * subset -> "printable characters" (ASCII 32 - 126). Replace
				 * all others with 0xFFFD (UNICODE replacement character).
				 */

                for(int i = 0; i < reasonBuffer.length(); i++) {
                    char c = reasonBuffer.charAt(i);

                    if((c >= 32) && (c <= 126)) {
                        continue;
                    }
                    reasonBuffer.setCharAt(i, '\uFFFD');
                }

                throw new IOException("Peer sent DISCONNECT message (reason code " + reason_code + "): "
                        + reasonBuffer.toString());
            }

			/*
             * Is it a KEX Packet?
			 */

            if((type == Packets.SSH_MSG_KEXINIT) || (type == Packets.SSH_MSG_NEWKEYS)
                    || ((type >= 30) && (type <= 49))) {
                km.handleMessage(msg, msglen);
                continue;
            }
            if(type == Packets.SSH_MSG_USERAUTH_SUCCESS) {
                tc.startCompression();
            }
            MessageHandler mh = null;

            for(HandlerEntry he : messageHandlers) {
                if((he.low <= type) && (type <= he.high)) {
                    mh = he.mh;
                    break;
                }
            }

            if(mh == null) {
                throw new IOException("Unexpected SSH message (type " + type + ")");
            }

            mh.handleMessage(msg, msglen);
        }
    }
}
