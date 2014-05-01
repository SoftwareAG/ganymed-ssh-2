/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import ch.ethz.ssh2.PacketFormatException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketChannelWindowAdjust {

    private final byte[] payload;

    public PacketChannelWindowAdjust(int recipientChannelID, int windowChange) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST);
        tw.writeUINT32(recipientChannelID);
        tw.writeUINT32(windowChange);
        payload = tw.getBytes();
    }

    public PacketChannelWindowAdjust(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_CHANNEL_WINDOW_ADJUST) {
            throw new IOException(
                    "This is not a SSH_MSG_CHANNEL_WINDOW_ADJUST! ("
                            + packet_type + ")"
            );
        }

        int recipientChannelID = tr.readUINT32();
        int windowChange = tr.readUINT32();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
