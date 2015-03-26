/*
 * Copyright (c) John Murray, 2015.
 *
 *   This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package burp;

import org.apache.jmeter.protocol.amf.util.AmfXmlConverter;

import java.util.List;

public class AMFUtils {
    public static byte[] serializeMagic = new byte[] {0x66, 0x6C, 0x65, 0x78}; //flex
    public static String AMFHeader = "application/x-amf";
    public static String SERIALIZEHEADER = "AMFSERIALIZED-GOODNESS";

	public static byte[] toXML(byte[] message, IExtensionHelpers helpers)
    {
		try {

            List<String> headers = helpers.analyzeRequest(message).getHeaders();
            int bodyOffset = helpers.analyzeRequest(message).getBodyOffset();
            byte[] body = new byte[message.length - bodyOffset];

            //copy it and convert it to XML
            System.arraycopy(message, bodyOffset, body, 0, message.length - bodyOffset);

            String xml = AmfXmlConverter.convertAmfMessageToXml(body, true);

            return helpers.buildHttpMessage(headers, xml.getBytes());

		} catch (Exception e) {
			e.printStackTrace();
			return message;
		}
	}

	public static byte[] fromXML(byte[] xml, IExtensionHelpers helpers)
    {

		try {
            // xstream doen't like newlines
            String cleanxml = helpers.bytesToString(xml).replace("\n", "");
            return AmfXmlConverter.convertXmlToAmfMessage(cleanxml);

		} catch (Exception ex) {
            System.out.println("Error deserializing XML " + ex.getMessage());
            return null;
		}
	}

    public static boolean isAMF(byte[] content, IExtensionHelpers helpers)
    {
        //if it has the magic bytes, or a content type of application/x-amf
        return (helpers.indexOf(content, helpers.stringToBytes(AMFUtils.AMFHeader), false, 0, content.length) > -1
                || helpers.indexOf(content, AMFUtils.serializeMagic, false, 0, content.length) > -1);
    }

    public static boolean hasMagicHeader(byte[] content, IExtensionHelpers helpers)
    {
        return helpers.indexOf(content, helpers.stringToBytes(AMFUtils.SERIALIZEHEADER), false, 0, content.length) > -1;
    }

}
