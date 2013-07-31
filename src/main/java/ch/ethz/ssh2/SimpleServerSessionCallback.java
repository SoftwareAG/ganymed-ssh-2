
package ch.ethz.ssh2;

import java.io.IOException;

/**
 * A basic ServerSessionCallback implementation.
 * <p>
 * Note: you should derive from this class instead of implementing
 * the {@link ServerSessionCallback} interface directly. This way
 * your code works also in case the interface gets extended in future
 * versions.
 * 
 * @author Christian
 *
 */
public class SimpleServerSessionCallback implements ServerSessionCallback
{
	public boolean allowPtyReq(ServerSession ss, PtySettings pty) throws IOException
	{
		return false;
	}

	public void handlePtyReq(ServerSession ss, PtySettings pty) throws IOException
	{
	}

	public boolean allowEnv(ServerSession ss, String name, String value) throws IOException
	{
		return true;
	}

	public void handleEnv(ServerSession ss, String name, String value) throws IOException
	{
	}

	public boolean allowShell(ServerSession ss) throws IOException
	{
		return false;
	}

	public void handleShell(ServerSession ss) throws IOException
	{
	}

	public boolean allowExec(ServerSession ss, String command) throws IOException
	{
		return false;
	}

	public void handleExec(ServerSession ss, String command) throws IOException
	{
	}

	public boolean allowSubsystem(ServerSession ss, String subsystem) throws IOException
	{
		return false;
	}

	public void handleSubsystem(ServerSession ss, String subsystem) throws IOException
	{
	}

	public void handleWindowChange(ServerSession ss, int term_width_columns, int term_height_rows,
			int term_width_pixels, int term_height_pixels) throws IOException
	{
	}

}
