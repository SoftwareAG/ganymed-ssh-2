/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketGlobalCancelForwardRequest {

    private final byte[] payload;

    public PacketGlobalCancelForwardRequest(boolean wantReply, String bindAddress, int bindPort) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_GLOBAL_REQUEST);

        tw.writeString("cancel-tcpip-forward");
        tw.writeBoolean(wantReply);
        tw.writeString(bindAddress);
        tw.writeUINT32(bindPort);

        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
