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
public final class PacketUserauthBanner {
    private final byte[] payload;

    private final String message;

    public PacketUserauthBanner(String message) {
        this.message = message;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_USERAUTH_BANNER);
        tw.writeString(message);
        tw.writeString("");
        payload = tw.getBytes();
    }

    public String getBanner() {
        return message;
    }

    public PacketUserauthBanner(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_USERAUTH_BANNER) {
            throw new PacketTypeException(packet_type);
        }
        message = tr.readString("UTF-8");
        String language = tr.readString();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
