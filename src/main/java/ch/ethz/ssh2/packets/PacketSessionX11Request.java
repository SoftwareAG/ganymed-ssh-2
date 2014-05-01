/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketSessionX11Request {
    private final byte[] payload;

    public PacketSessionX11Request(int recipientChannelID, boolean wantReply, boolean singleConnection,
                                   String x11AuthenticationProtocol, String x11AuthenticationCookie, int x11ScreenNumber) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
        tw.writeUINT32(recipientChannelID);
        tw.writeString("x11-req");
        tw.writeBoolean(wantReply);

        tw.writeBoolean(singleConnection);
        tw.writeString(x11AuthenticationProtocol);
        tw.writeString(x11AuthenticationCookie);
        tw.writeUINT32(x11ScreenNumber);

        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
