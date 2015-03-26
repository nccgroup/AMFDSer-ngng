package burp;
import flex.messaging.io.ArrayList;

import javax.swing.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.List;

public class AMFMenu implements IContextMenuFactory {
	private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

	public AMFMenu(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
		this.callbacks = callbacks;
        this.helpers = helpers;
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		JMenuItem sendAMFToIntruderMenu = new JMenuItem("Send Deserialized AMF to Intruder");
		sendAMFToIntruderMenu.addMouseListener(new MouseListener() {
			@Override
			public void mouseClicked(MouseEvent arg0) {

			}

			@Override
			public void mouseEntered(MouseEvent arg0) {
			}

			@Override
			public void mouseExited(MouseEvent arg0) {
			}

			@Override
			public void mousePressed(MouseEvent arg0) {
				IHttpRequestResponse[] selectedMessages = invocation.getSelectedMessages();
				for (IHttpRequestResponse iReqResp : selectedMessages) {
					IHttpService httpService = iReqResp.getHttpService();

                    //append our custom header and send to intruder
                    List<String> headers = helpers.analyzeRequest(iReqResp.getRequest()).getHeaders();
                    headers.add(AMFUtils.SERIALIZEHEADER);
                    byte[] message = iReqResp.getRequest();

                    int bodyOffset = helpers.analyzeRequest(message).getBodyOffset();
                    byte[] body = new byte[message.length - bodyOffset];

                    //copy it and convert it to XML
                    System.arraycopy(message, bodyOffset, body, 0, message.length - bodyOffset);

					callbacks.sendToIntruder(httpService.getHost(), httpService.getPort(), (httpService.getProtocol().equals("https") ? true : false),
                            AMFUtils.toXML(helpers.buildHttpMessage(headers, body), helpers));
				}
			}

			@Override
			public void mouseReleased(MouseEvent arg0) {
			}
		});

		List<JMenuItem> menus = new ArrayList();
		menus.add(sendAMFToIntruderMenu);
		return menus;
	}

}
