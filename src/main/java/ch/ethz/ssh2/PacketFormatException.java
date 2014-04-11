package ch.ethz.ssh2;

import java.io.IOException;

/**
 * @version $Id:$
 */
public class PacketFormatException extends IOException
{

	public PacketFormatException(String message)
	{
		super(message);
	}
}
