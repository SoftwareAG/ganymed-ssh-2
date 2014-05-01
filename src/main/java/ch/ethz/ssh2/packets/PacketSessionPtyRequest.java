/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketSessionPtyRequest {
    private final byte[] payload;

    public PacketSessionPtyRequest(int recipientChannelID, boolean wantReply, String term,
                                   int character_width, int character_height, int pixel_width, int pixel_height,
                                   byte[] terminal_modes) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
        tw.writeUINT32(recipientChannelID);
        tw.writeString("pty-req");
        tw.writeBoolean(wantReply);
        tw.writeString(term);
        tw.writeUINT32(character_width);
        tw.writeUINT32(character_height);
        tw.writeUINT32(pixel_width);
        tw.writeUINT32(pixel_height);
        tw.writeString(terminal_modes, 0, terminal_modes.length);

        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
