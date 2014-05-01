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
public final class PacketChannelOpenFailure {

    private final byte[] payload;

    public PacketChannelOpenFailure(int recipientChannelID, int reasonCode, String description,
                                    String languageTag) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_OPEN_FAILURE);
        tw.writeUINT32(recipientChannelID);
        tw.writeUINT32(reasonCode);
        tw.writeString(description);
        tw.writeString(languageTag);
        payload = tw.getBytes();
    }

    public PacketChannelOpenFailure(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_CHANNEL_OPEN_FAILURE) {
            throw new IOException(
                    "This is not a SSH_MSG_CHANNEL_OPEN_FAILURE! ("
                            + packet_type + ")"
            );
        }

        int recipientChannelID = tr.readUINT32();
        int reasonCode = tr.readUINT32();
        String description = tr.readString();
        String languageTag = tr.readString();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public byte[] getPayload() {
        return payload;
    }
}
