/*
 * Copyright (c) 2012-2013 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2;

import java.io.IOException;

/**
 * The interface for an object that receives events based on requests that
 * a client sends on a session channel.
 * <p>
 * CAUTION: All these event methods are being called from the receiver thread. The receiving of messages will be blocked until
 * the event handler returns.
 * <p>
 * If you want to signal a fatal error, then please throw an <code>IOException</code>. Currently, this will
 * tear down the whole SSH connection.
 * 
 * @see ServerSession
 * 
 * @author Christian
 *
 */
public interface ServerSessionCallback
{
	public boolean allowPtyReq(ServerSession ss, PtySettings pty) throws IOException;
	public void handlePtyReq(ServerSession ss, PtySettings pty) throws IOException;

	public boolean allowEnv(ServerSession ss, String name, String value) throws IOException;
	public void handleEnv(ServerSession ss, String name, String value) throws IOException;

	public boolean allowShell(ServerSession ss) throws IOException;
	public void handleShell(ServerSession ss) throws IOException;

	public boolean allowExec(ServerSession ss, String command) throws IOException;
	public void handleExec(ServerSession ss, String command) throws IOException;

	public boolean allowSubsystem(ServerSession ss, String subsystem) throws IOException;
	public void handleSubsystem(ServerSession ss, String subsystem) throws IOException;

	/**
	 * When the window (terminal) size changes on the client side, it MAY send a message to the other side to inform it of the new dimensions.
	 * 
	 * @param ss
	 * @param term_width_columns
	 * @param term_height_rows
	 * @param term_width_pixels
	 */
	public void handleWindowChange(ServerSession ss, int term_width_columns, int term_height_rows,
			int term_width_pixels, int term_height_pixels) throws IOException;

	/**
	 * A signal can be delivered to the remote process/service. Some systems may not implement signals, in which case they SHOULD ignore this message.
	 * 
	 * @param ss the corresponding session
	 * @param signal (without the "SIG" prefix)
	 * @return
	 * @throws IOException
	 */

}
