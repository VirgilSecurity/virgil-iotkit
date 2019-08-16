/* ====================================================================
 * Copyright (c) 1995-1999 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#ifndef _BASE64_H_
#define _BASE64_H_

#ifdef __cplusplus
extern "C" {
#endif
/** Get Base64 Decoded len
 *
 * Gives the length of the data that will be obtained after decoding the given
 * base64 encoded string
 *
 * \param[in] in Pointer to Base64 encoded string.
 * \param[in] inlen Length of the Base64 encoded string.
 *
 * \return Length of the data that will be obtained after decoding
 */
int
base64decode_len(const char *in, int inlen);

/** Base64 Decode string
 *
 * This function decodes the given Base64 encoded string into raw binary data.
 *
 * \note This function an do in-place decoding. So, the same buffer can be used
 * for input as well as output.
 *
 * \param[in] in Pointer to Base64 encoded string.
 * \param[in] inlen Length of the Base64 encoded string.
 * \param[out] out Pointer to the output buffer that will be populated by the
 * function.
 * \param[in,out] outlen Holds the length of the output buffer and is populated
 * with the length of the decoded data by this function.
 *
 * \return -1 on failure
 * \return 0 on success
 */
int
base64decode(const char *in, int inlen, unsigned char *out, int *outlen);

/** Get Base64 Encoded len
 *
 * Gives the length of the string that will be obtained after encoding the
 * given binary data
 *
 * \param[in] Length of the input binary data.
 *
 * \return Length of the string that will be obtained after encoding
 */
int
base64encode_len(int len);

/** Base64 Encode data
 *
 * This function encodes the given raw binary data into a Base64 encoded string.
 *
 * \param[in] in Pointer to raw binary data
 * \param[in] inlen Length if the binary data (in bytes)
 * \param[out] out Pointer to the output buffer that will be populated by the
 * function
 * \param[in/out] outlen Holds the length of the output buffer and is populated
 * with the length of the encoded data by this function. The required length
 * of the buffer can be obtained using base64encode_len().
 *
 * \return -1 on failure
 * \return 0 on success
 */
int
base64encode(const unsigned char *in, int inlen, char *out, int *outlen);

#ifdef __cplusplus
}
#endif

#endif /* _BASE64_H_ */
