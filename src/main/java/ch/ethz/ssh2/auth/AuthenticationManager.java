/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.auth;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import ch.ethz.ssh2.InteractiveCallback;
import ch.ethz.ssh2.PacketTypeException;
import ch.ethz.ssh2.crypto.PEMDecoder;
import ch.ethz.ssh2.packets.PacketServiceAccept;
import ch.ethz.ssh2.packets.PacketServiceRequest;
import ch.ethz.ssh2.packets.PacketUserauthBanner;
import ch.ethz.ssh2.packets.PacketUserauthFailure;
import ch.ethz.ssh2.packets.PacketUserauthInfoRequest;
import ch.ethz.ssh2.packets.PacketUserauthInfoResponse;
import ch.ethz.ssh2.packets.PacketUserauthRequestInteractive;
import ch.ethz.ssh2.packets.PacketUserauthRequestNone;
import ch.ethz.ssh2.packets.PacketUserauthRequestPassword;
import ch.ethz.ssh2.packets.PacketUserauthRequestPublicKey;
import ch.ethz.ssh2.packets.Packets;
import ch.ethz.ssh2.packets.TypesWriter;
import ch.ethz.ssh2.signature.DSAPrivateKey;
import ch.ethz.ssh2.signature.DSASHA1Verify;
import ch.ethz.ssh2.signature.DSASignature;
import ch.ethz.ssh2.signature.RSAPrivateKey;
import ch.ethz.ssh2.signature.RSASHA1Verify;
import ch.ethz.ssh2.signature.RSASignature;
import ch.ethz.ssh2.transport.ClientTransportManager;
import ch.ethz.ssh2.transport.MessageHandler;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public class AuthenticationManager implements MessageHandler {
    private ClientTransportManager tm;

    private final BlockingQueue<byte[]> packets
            = new ArrayBlockingQueue<byte[]>(5);

    private boolean connectionClosed = false;

    private String banner;

    private Set<String> remainingMethods
            = new HashSet<String>();

    private boolean isPartialSuccess = false;

    private boolean authenticated = false;
    private boolean initDone = false;

    public AuthenticationManager(ClientTransportManager tm) {
        this.tm = tm;
    }

    private byte[] deQueue() throws IOException {
        if(connectionClosed) {
            throw tm.getReasonClosedCause();
        }
        // Wait for packet
        try {
            return packets.take();
        }
        catch(InterruptedException e) {
            throw new InterruptedIOException(e.getMessage());
        }
    }

    byte[] getNextMessage() throws IOException {
        while(true) {
            byte[] message = deQueue();
            switch(message[0]) {
                case Packets.SSH_MSG_USERAUTH_BANNER:
                    // The server may send an SSH_MSG_USERAUTH_BANNER message at any
                    // time after this authentication protocol starts and before
                    // authentication is successful.
                    PacketUserauthBanner sb = new PacketUserauthBanner(message);
                    banner = sb.getBanner();
                    break;
                default:
                    return message;
            }
        }
    }

    public Set<String> getRemainingMethods(String user) throws IOException {
        initialize(user);
        return remainingMethods;
    }

    public String getBanner() {
        return banner;
    }

    public boolean getPartialSuccess() {
        return isPartialSuccess;
    }

    private boolean initialize(String user) throws IOException {
        if(initDone == false) {
            tm.registerMessageHandler(this, 0, 255);

            PacketServiceRequest sr = new PacketServiceRequest("ssh-userauth");
            tm.sendMessage(sr.getPayload());

            final PacketServiceAccept accept = new PacketServiceAccept(this.getNextMessage());

            PacketUserauthRequestNone auth = new PacketUserauthRequestNone("ssh-connection", user);
            tm.sendMessage(auth.getPayload());

            byte[] message = this.getNextMessage();
            initDone = true;
            switch(message[0]) {
                case Packets.SSH_MSG_USERAUTH_SUCCESS:
                    authenticated = true;
                    tm.removeMessageHandler(this);
                    return true;
                case Packets.SSH_MSG_USERAUTH_FAILURE:
                    PacketUserauthFailure puf = new PacketUserauthFailure(message);
                    remainingMethods = puf.getAuthThatCanContinue();
                    isPartialSuccess = puf.isPartialSuccess();
                    return false;
            }
            throw new PacketTypeException(message[0]);
        }
        return authenticated;
    }

    public boolean authenticatePublicKey(String user, AgentProxy proxy) throws IOException {
        initialize(user);

        boolean success;
        for(AgentIdentity identity : proxy.getIdentities()) {
            success = authenticatePublicKey(user, identity);
            if(success) {
                return true;
            }
        }
        return false;
    }

    private boolean authenticatePublicKey(String user, AgentIdentity identity) throws IOException {
        if(!remainingMethods.contains("publickey")) {
            throw new IOException("Authentication method not supported");
        }

        byte[] pubKeyBlob = identity.getPublicKeyBlob();
        if(pubKeyBlob == null) {
            return false;
        }

        TypesWriter tw = new TypesWriter();
        byte[] H = tm.getSessionIdentifier();

        tw.writeString(H, 0, H.length);
        tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
        tw.writeString(user);
        tw.writeString("ssh-connection");
        tw.writeString("publickey");
        tw.writeBoolean(true);
        tw.writeString(identity.getAlgName());
        tw.writeString(pubKeyBlob, 0, pubKeyBlob.length);

        byte[] msg = tw.getBytes();
        byte[] response = identity.sign(msg);

        PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey(
                "ssh-connection", user, identity.getAlgName(), pubKeyBlob, response);
        tm.sendMessage(ua.getPayload());

        byte[] message = getNextMessage();
        final int type = message[0];
        switch(type) {
            case Packets.SSH_MSG_USERAUTH_SUCCESS:
                authenticated = true;
                tm.removeMessageHandler(this);
                return true;
            case Packets.SSH_MSG_USERAUTH_FAILURE:
                PacketUserauthFailure puf = new PacketUserauthFailure(message);

                remainingMethods = puf.getAuthThatCanContinue();
                isPartialSuccess = puf.isPartialSuccess();

                return false;
        }
        throw new PacketTypeException(type);
    }

    public boolean authenticatePublicKey(String user, char[] PEMPrivateKey, String password, SecureRandom rnd)
            throws IOException {
        try {
            initialize(user);

            if(!remainingMethods.contains("publickey")) {
                throw new IOException("Authentication method publickey not supported by the server at this stage.");
            }

            Object key = PEMDecoder.decode(PEMPrivateKey, password);

            if(key instanceof DSAPrivateKey) {
                DSAPrivateKey pk = (DSAPrivateKey) key;

                byte[] pk_enc = DSASHA1Verify.encodeSSHDSAPublicKey(pk.getPublicKey());

                TypesWriter tw = new TypesWriter();

                byte[] H = tm.getSessionIdentifier();

                tw.writeString(H, 0, H.length);
                tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
                tw.writeString(user);
                tw.writeString("ssh-connection");
                tw.writeString("publickey");
                tw.writeBoolean(true);
                tw.writeString("ssh-dss");
                tw.writeString(pk_enc, 0, pk_enc.length);

                byte[] msg = tw.getBytes();

                DSASignature ds = DSASHA1Verify.generateSignature(msg, pk, rnd);

                byte[] ds_enc = DSASHA1Verify.encodeSSHDSASignature(ds);

                PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
                        "ssh-dss", pk_enc, ds_enc);
                tm.sendMessage(ua.getPayload());
            }
            else if(key instanceof RSAPrivateKey) {
                RSAPrivateKey pk = (RSAPrivateKey) key;

                byte[] pk_enc = RSASHA1Verify.encodeSSHRSAPublicKey(pk.getPublicKey());

                TypesWriter tw = new TypesWriter();
                {
                    byte[] H = tm.getSessionIdentifier();

                    tw.writeString(H, 0, H.length);
                    tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
                    tw.writeString(user);
                    tw.writeString("ssh-connection");
                    tw.writeString("publickey");
                    tw.writeBoolean(true);
                    tw.writeString("ssh-rsa");
                    tw.writeString(pk_enc, 0, pk_enc.length);
                }

                byte[] msg = tw.getBytes();

                RSASignature ds = RSASHA1Verify.generateSignature(msg, pk);

                byte[] rsa_sig_enc = RSASHA1Verify.encodeSSHRSASignature(ds);

                PacketUserauthRequestPublicKey ua = new PacketUserauthRequestPublicKey("ssh-connection", user,
                        "ssh-rsa", pk_enc, rsa_sig_enc);
                tm.sendMessage(ua.getPayload());
            }
            else {
                throw new IOException("Unknown private key type returned by the PEM decoder.");
            }
            byte[] message = getNextMessage();
            final int type = message[0];
            switch(type) {
                case Packets.SSH_MSG_USERAUTH_SUCCESS:
                    authenticated = true;
                    tm.removeMessageHandler(this);
                    return true;
                case Packets.SSH_MSG_USERAUTH_FAILURE:
                    PacketUserauthFailure puf = new PacketUserauthFailure(message);

                    remainingMethods = puf.getAuthThatCanContinue();
                    isPartialSuccess = puf.isPartialSuccess();

                    return false;
            }
            throw new PacketTypeException(type);
        }
        catch(IOException e) {
            tm.close(e);
            throw e;
        }
    }

    public boolean authenticateNone(String user) throws IOException {
        try {
            initialize(user);
            return authenticated;
        }
        catch(IOException e) {
            tm.close(e);
            throw e;
        }
    }

    public boolean authenticatePassword(String user, String pass) throws IOException {
        try {
            initialize(user);

            if(!remainingMethods.contains("password")) {
                throw new IOException("Authentication method not supported");
            }

            PacketUserauthRequestPassword ua = new PacketUserauthRequestPassword("ssh-connection", user, pass);
            tm.sendMessage(ua.getPayload());

            byte[] message = getNextMessage();
            final int type = message[0];
            switch(type) {
                case Packets.SSH_MSG_USERAUTH_SUCCESS:
                    authenticated = true;
                    tm.removeMessageHandler(this);
                    return true;
                case Packets.SSH_MSG_USERAUTH_FAILURE:
                    PacketUserauthFailure puf = new PacketUserauthFailure(message);
                    remainingMethods = puf.getAuthThatCanContinue();
                    isPartialSuccess = puf.isPartialSuccess();
                    return false;
            }
            throw new PacketTypeException(type);
        }
        catch(IOException e) {
            tm.close(e);
            throw e;
        }
    }

    public boolean authenticateInteractive(String user, String[] submethods, InteractiveCallback cb) throws IOException {
        try {
            initialize(user);

            if(!remainingMethods.contains("keyboard-interactive")) {
                throw new IOException(
                        "Authentication method keyboard-interactive not supported by the server at this stage.");
            }

            PacketUserauthRequestInteractive ua = new PacketUserauthRequestInteractive("ssh-connection", user,
                    submethods);

            tm.sendMessage(ua.getPayload());

            while(true) {
                byte[] message = getNextMessage();
                final int type = message[0];
                switch(type) {
                    case Packets.SSH_MSG_USERAUTH_SUCCESS:
                        authenticated = true;
                        tm.removeMessageHandler(this);
                        return true;
                    case Packets.SSH_MSG_USERAUTH_FAILURE:
                        PacketUserauthFailure puf = new PacketUserauthFailure(message);

                        remainingMethods = puf.getAuthThatCanContinue();
                        isPartialSuccess = puf.isPartialSuccess();

                        return false;
                    case Packets.SSH_MSG_USERAUTH_INFO_REQUEST:
                        PacketUserauthInfoRequest info = new PacketUserauthInfoRequest(message);
                        String[] responses;
                        try {
                            responses = cb.replyToChallenge(info.getName(), info.getInstruction(), info.getNumPrompts(),
                                    info.getPrompt(), info.getEcho());
                        }
                        catch(Exception e) {
                            throw new IOException("Exception in callback.", e);
                        }
                        PacketUserauthInfoResponse puir = new PacketUserauthInfoResponse(responses);
                        tm.sendMessage(puir.getPayload());
                        continue;
                }
                throw new PacketTypeException(type);
            }
        }
        catch(IOException e) {
            tm.close(e);
            throw e;
        }
    }

    @Override
    public void handleFailure(final IOException failure) {
        connectionClosed = true;
    }

    @Override
    public void handleMessage(byte[] message) throws IOException {
        packets.add(message);
    }
}
