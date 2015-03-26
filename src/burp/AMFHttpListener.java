package burp;

import java.util.List;

public class AMFHttpListener implements IHttpListener {

    private IExtensionHelpers helpers;
    public AMFHttpListener(IExtensionHelpers helpers)
    {
        this.helpers = helpers;
    }
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER || toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER)
        {

            //if it is a request, check to see if it has the magic header
            if (messageIsRequest && messageInfo != null && AMFUtils.hasMagicHeader(messageInfo.getRequest(), helpers)) {

                //if the request has the custom header, remove it
                List<String> headers = helpers.analyzeRequest(messageInfo.getRequest()).getHeaders();
                headers.remove(AMFUtils.SERIALIZEHEADER);

                //extract the body
                int bodyOffset = helpers.analyzeRequest(messageInfo.getRequest()).getBodyOffset();
                byte[] request = messageInfo.getRequest();
                int bodyLength = request.length - bodyOffset;

                byte[] body = new byte[bodyLength];
                System.arraycopy(request, bodyOffset, body, 0, bodyLength);

                //convert it back to a serialized object and create an http message (without the magic header)
                byte[] newHTTPMessage = helpers.buildHttpMessage(headers, AMFUtils.fromXML(body, helpers));
                //System.out.println(helpers.bytesToString(newHTTPMessage));

                //update the current message to this one
                messageInfo.setRequest(newHTTPMessage);
            }

            //if it is a response, and looks like java, and comes from the scanner convert it to XML so that stack traces and error messages, etc. can be picked up on)
            else if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER && AMFUtils.isAMF(messageInfo.getResponse(), helpers))
            {
                try {
                    byte[] XML = AMFUtils.toXML(messageInfo.getResponse(), helpers);
                    List<String> headers = helpers.analyzeRequest(messageInfo.getResponse()).getHeaders();

                    //set the request body here so burp actually sees it
                    messageInfo.setResponse(helpers.buildHttpMessage(headers, XML));

                } catch (Exception ex) {
                    System.out.println("Error deserializing standard (intruder/scanner) response " + ex.getMessage());
                }
            }
        }
	}
}