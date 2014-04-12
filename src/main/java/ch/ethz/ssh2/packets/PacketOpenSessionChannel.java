/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * PacketOpenSessionChannel.
 * 
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public class PacketOpenSessionChannel
{
	byte[] payload;

	int channelID;
	int initialWindowSize;
	int maxPacketSize;

	public PacketOpenSessionChannel(int channelID, int initialWindowSize,
			int maxPacketSize)
	{
		this.channelID = channelID;
		this.initialWindowSize = initialWindowSize;
		this.maxPacketSize = maxPacketSize;
	}

	public PacketOpenSessionChannel(byte payload[], int off, int len) throws IOException
	{
		this.payload = new byte[len];
		System.arraycopy(payload, off, this.payload, 0, len);

		TypesReader tr = new TypesReader(payload);

		int packet_type = tr.readByte();

		if (packet_type != Packets.SSH_MSG_CHANNEL_OPEN)
		{
			throw new PacketTypeException(packet_type);
		}
		channelID = tr.readUINT32();
		initialWindowSize = tr.readUINT32();
		maxPacketSize = tr.readUINT32();

		if (tr.remain() != 0)
			throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
	}

	public byte[] getPayload()
	{
		if (payload == null)
		{
			TypesWriter tw = new TypesWriter();
			tw.writeByte(Packets.SSH_MSG_CHANNEL_OPEN);
			tw.writeString("session");
			tw.writeUINT32(channelID);
			tw.writeUINT32(initialWindowSize);
			tw.writeUINT32(maxPacketSize);
			payload = tw.getBytes();
		}
		return payload;
	}
}
