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
public final class PacketChannelOpenConfirmation {

    private final byte[] payload;

    private final int recipientChannelID;
    private final int senderChannelID;
    private final int initialWindowSize;
    private final int maxPacketSize;

    public PacketChannelOpenConfirmation(int recipientChannelID, int senderChannelID, int initialWindowSize,
                                         int maxPacketSize) {
        this.recipientChannelID = recipientChannelID;
        this.senderChannelID = senderChannelID;
        this.initialWindowSize = initialWindowSize;
        this.maxPacketSize = maxPacketSize;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
        tw.writeUINT32(recipientChannelID);
        tw.writeUINT32(senderChannelID);
        tw.writeUINT32(initialWindowSize);
        tw.writeUINT32(maxPacketSize);
        payload = tw.getBytes();
    }

    public PacketChannelOpenConfirmation(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_CHANNEL_OPEN_CONFIRMATION) {
            throw new PacketTypeException(packet_type);
        }

        recipientChannelID = tr.readUINT32();
        senderChannelID = tr.readUINT32();
        initialWindowSize = tr.readUINT32();
        maxPacketSize = tr.readUINT32();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public int getRecipientChannelID() {
        return recipientChannelID;
    }

    public int getSenderChannelID() {
        return senderChannelID;
    }

    public int getInitialWindowSize() {
        return initialWindowSize;
    }

    public int getMaxPacketSize() {
        return maxPacketSize;
    }

    public byte[] getPayload() {
        return payload;
    }
}
