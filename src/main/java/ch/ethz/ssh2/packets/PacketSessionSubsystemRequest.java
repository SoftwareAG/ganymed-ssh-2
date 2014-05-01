/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketSessionSubsystemRequest {
    private final byte[] payload;

    public PacketSessionSubsystemRequest(int recipientChannelID, boolean wantReply, String subsystem) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
        tw.writeUINT32(recipientChannelID);
        tw.writeString("subsystem");
        tw.writeBoolean(wantReply);
        tw.writeString(subsystem);
        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
