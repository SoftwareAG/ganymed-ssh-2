/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;
import java.math.BigInteger;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * @author Christian Plattner
 * @version $Id$
 */
public final class PacketKexDhGexReply {

    private final byte[] hostKey;
    private final BigInteger f;
    private final byte[] signature;

    public PacketKexDhGexReply(byte payload[]) throws IOException {
        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_KEX_DH_GEX_REPLY) {
            throw new PacketTypeException(packet_type);
        }

        hostKey = tr.readByteString();
        f = tr.readMPINT();
        signature = tr.readByteString();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public BigInteger getF() {
        return f;
    }

    public byte[] getHostKey() {
        return hostKey;
    }

    public byte[] getSignature() {
        return signature;
    }
}
