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
public final class PacketUserauthRequestPassword {

    private final byte[] payload;

    public PacketUserauthRequestPassword(String serviceName, String user, String pass) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_USERAUTH_REQUEST);
        tw.writeString(user);
        tw.writeString(serviceName);
        tw.writeString("password");
        tw.writeBoolean(false);
        tw.writeString(pass);
        payload = tw.getBytes();
    }

    public PacketUserauthRequestPassword(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_USERAUTH_REQUEST) {
            throw new PacketTypeException(packet_type);
        }
        String userName = tr.readString();
        String serviceName = tr.readString();

        String method = tr.readString();

        if(!method.equals("password")) {
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
