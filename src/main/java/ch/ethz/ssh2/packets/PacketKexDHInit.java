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
public final class PacketKexDHInit {

    private final byte[] payload;

    private final BigInteger e;

    public PacketKexDHInit(BigInteger e) {
        this.e = e;
        TypesWriter tw = new TypesWriter();
        tw.writeByte(Packets.SSH_MSG_KEXDH_INIT);
        tw.writeMPInt(e);
        payload = tw.getBytes();
    }

    public PacketKexDHInit(byte payload[]) throws IOException {
        this.payload = payload;

        TypesReader tr = new TypesReader(payload);

        int packet_type = tr.readByte();

        if(packet_type != Packets.SSH_MSG_KEXDH_INIT) {
            throw new PacketTypeException(packet_type);
        }

        e = tr.readMPINT();

        if(tr.remain() != 0) {
            throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
        }
    }

    public BigInteger getE() {
        return e;
    }

    public byte[] getPayload() {
        return payload;
    }
}
