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
public final class PacketOpenSessionChannel {
    private final byte[] payload;

    public PacketOpenSessionChannel(int channelID, int initialWindowSize, int maxPacketSize) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_OPEN);
        tw.writeString("session");
        tw.writeUINT32(channelID);
        tw.writeUINT32(initialWindowSize);
        tw.writeUINT32(maxPacketSize);
        payload = tw.getBytes();
    }

    public PacketOpenSessionChannel(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_CHANNEL_OPEN) {
            throw new PacketTypeException(packet_type);
        }

        int channelID = tr.readUINT32();
        int initialWindowSize = tr.readUINT32();
        int maxPacketSize = tr.readUINT32();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
