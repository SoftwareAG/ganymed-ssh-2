/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import ch.ethz.ssh2.DHGexParameters;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketKexDhGexRequest {
    private final byte[] payload;

    public PacketKexDhGexRequest(DHGexParameters para) {
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_KEX_DH_GEX_REQUEST);
        tw.writeUINT32(para.getMin_group_len());
        tw.writeUINT32(para.getPref_group_len());
        tw.writeUINT32(para.getMax_group_len());
        payload = tw.getBytes();
    }

    public byte[] getPayload() {
        return payload;
    }
}
