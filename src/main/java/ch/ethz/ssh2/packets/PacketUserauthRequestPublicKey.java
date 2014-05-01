/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketUserauthRequestPublicKey {

    private final byte[] payload;

    public PacketUserauthRequestPublicKey(String serviceName, String user,
                                          String pkAlgorithmName, byte[] pk, byte[] sig) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
        tw.writeString(user);
        tw.writeString(serviceName);
        tw.writeString("publickey");
        tw.writeBoolean(true);
        tw.writeString(pkAlgorithmName);
        tw.writeString(pk, 0, pk.length);
        tw.writeString(sig, 0, sig.length);
        payload = tw.getBytes();
    }

    public PacketUserauthRequestPublicKey(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_USERAUTH_REQUEST) {
            throw new PacketTypeException(packet_type);
        }
        String userName = tr.readString();
        String serviceName = tr.readString();

        String method = tr.readString();

        if(!method.equals("publickey")) {
            throw new IOException(String.format("Unexpected method %s", method));
        }
        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
