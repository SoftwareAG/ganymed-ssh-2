/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketSessionExecCommand {
    private final byte[] payload;

    public PacketSessionExecCommand(int recipientChannelID, boolean wantReply, String command, String charsetName) throws UnsupportedEncodingException {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_CHANNEL_REQUEST);
        tw.writeUINT32(recipientChannelID);
        tw.writeString("exec");
        tw.writeBoolean(wantReply);
        tw.writeString(command, charsetName);
        payload = tw.getBytes();
    }

    public byte[] getPayload() throws IOException {
        return payload;
    }
}
