/*
 * Copyright (c) 2006-2014 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.crypto;

import java.io.IOException;

/**
 * @version $Id: PEMDecryptException.java 5865 2010-03-27 03:28:11Z dkocher $
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
