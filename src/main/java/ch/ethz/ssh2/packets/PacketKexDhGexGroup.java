/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import java.math.BigInteger;

import ch.ethz.ssh2.PacketFormatException;

/**
 * PacketKexDhGexGroup.
 * 
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public class PacketKexDhGexGroup
{
	byte[] payload;

	BigInteger p;
	BigInteger g;

	public PacketKexDhGexGroup(byte payload[], int off, int len) throws IOException
	{
		this.payload = new byte[len];
		System.arraycopy(payload, off, this.payload, 0, len);

		TypesReader tr = new TypesReader(payload, off, len);

		int packet_type = tr.readByte();

		if (packet_type != Packets.SSH_MSG_KEX_DH_GEX_GROUP)
			throw new IllegalArgumentException(
					"This is not a SSH_MSG_KEX_DH_GEX_GROUP! (" + packet_type
							+ ")");

		p = tr.readMPINT();
		g = tr.readMPINT();

		if (tr.remain() != 0)
		{
			throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
		}
	}

	public BigInteger getG()
	{
		return g;
	}

	public BigInteger getP()
	{
		return p;
	}
}
