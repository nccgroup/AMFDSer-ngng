package burp;
import org.apache.jmeter.protocol.amf.util.AmfXmlConverter;

import java.awt.*;

 class AMFDeserializerTab implements IMessageEditorTab
 {
	private ITextEditor txtInput;
	private byte[] currentMessage;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	public AMFDeserializerTab(IMessageEditorController controller, boolean editable, IBurpExtenderCallbacks callbacks2, IExtensionHelpers helpers2) {
		callbacks = callbacks2;
		helpers = helpers2;
		// create an instance of Burp's text editor, to display our deserialized
		// data
		txtInput = callbacks.createTextEditor();
		txtInput.setEditable(editable);
	}

	//
	// implement IMessageEditorTab
	//

	@Override
	public String getTabCaption() {
		return "Deserialized AMF";
	}

	@Override
	public Component getUiComponent() {
		return txtInput.getComponent();
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		return AMFUtils.isAMF(content, helpers);
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		if (content == null) {
			// clear our display
			txtInput.setText(null);
			txtInput.setEditable(false);
		} else {

            //grab body
            int bodyOffset = helpers.analyzeRequest(content).getBodyOffset();
            byte[] body = new byte[content.length - bodyOffset];

            //copy it and convert it to XML
            System.arraycopy(content, bodyOffset, body, 0, content.length - bodyOffset);

			// deserialize the parameter value
			txtInput.setText((AmfXmlConverter.convertAmfMessageToXml(body, true)).getBytes());
			txtInput.setEditable(true);
		}

		// remember the displayed content
		currentMessage = content;
	}

	@Override
	public byte[] getMessage() {
		// determine whether the user modified the deserialized data
		if (txtInput.isTextModified()) {
			// reserialize the data
            byte[] newBody = AMFUtils.fromXML(txtInput.getText(), helpers);
            if (newBody == null)
            {
                return currentMessage;
            }
            return helpers.buildHttpMessage(helpers.analyzeRequest(currentMessage).getHeaders(), newBody);

		} else
			return currentMessage;
	}

	@Override
	public boolean isModified() {
		return txtInput.isTextModified();
	}

	@Override
	public byte[] getSelectedData() {
		return txtInput.getSelectedText();
	}
}