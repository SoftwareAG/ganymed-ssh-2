/*
 * Copyright (c) 2012-2013 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */

package ch.ethz.ssh2;

public interface ServerAuthenticationCallback
{
	public final String METHOD_HOSTBASED = "hostbased";
	public final String METHOD_PUBLICKEY = "publickey";
	public final String METHOD_PASSWORD = "password";

	/**
	 * Called when the client enters authentication.
	 * This gives you the chance to set a custom authentication banner
	 * for this SSH-2 session. This is the first method called in this interface.
	 * It will only called at most once per <code>ServerConnection</code>.
	 * 
	 * @param sc The corresponding <code>ServerConnection</code>
	 * @return The authentication banner or <code>NULL</code> in case no banner should be send.
	 */
	public String initAuthentication(ServerConnection sc);

	public String[] getRemainingAuthMethods(ServerConnection sc);

	public boolean authenticateWithNone(ServerConnection sc, String username);

	public boolean authenticateWithPassword(ServerConnection sc, String username, String password);

	public boolean authenticateWithPublicKey(ServerConnection sc, String username, String algorithm, byte[] publickey,
			byte[] signature);
}
