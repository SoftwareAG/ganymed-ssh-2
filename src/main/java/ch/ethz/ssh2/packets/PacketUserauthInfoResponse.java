/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketUserauthInfoResponse {
    private final byte[] payload;

    public PacketUserauthInfoResponse(String[] responses) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_USERAUTH_INFO_RESPONSE);
        tw.writeUINT32(responses.length);
        for(String response : responses) {
            tw.writeString(response);
        }
        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
