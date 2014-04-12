/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.packets;

import java.io.IOException;

import ch.ethz.ssh2.PacketFormatException;
import ch.ethz.ssh2.PacketTypeException;

/**
 * PacketUserauthBanner.
 * 
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public class PacketUserauthBanner
{
	byte[] payload;

	String message;
	String language;

	public PacketUserauthBanner(String message, String language)
	{
		this.message = message;
		this.language = language;
	}

	public String getBanner()
	{
		return message;
	}
	
	public PacketUserauthBanner(byte payload[], int off, int len) throws IOException
	{
		this.payload = new byte[len];
		System.arraycopy(payload, off, this.payload, 0, len);

		TypesReader tr = new TypesReader(payload, off, len);

		int packet_type = tr.readByte();

		if (packet_type != Packets.SSH_MSG_USERAUTH_BANNER)
		{
			throw new PacketTypeException(packet_type);
		}
		message = tr.readString("UTF-8");
		language = tr.readString();

		if (tr.remain() != 0)
			throw new PacketFormatException(String.format("Padding in %s", Packets.getMessageName(packet_type)));
	}

	public byte[] getPayload()
	{
		if (payload == null)
		{
			TypesWriter tw = new TypesWriter();
			tw.writeByte(Packets.SSH_MSG_USERAUTH_BANNER);
			tw.writeString(message);
			tw.writeString(language);
			payload = tw.getBytes();
		}
		return payload;
	}
}
