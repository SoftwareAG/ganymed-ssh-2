/*
 * Copyright (c) 2006-2014 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.crypto;

import java.io.IOException;

/**
 * @version $Id$
 */
public class PEMDecryptException extends IOException
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public PEMDecryptException(String message)
	{
		super(message);
	}
}
