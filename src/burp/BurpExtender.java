package burp;


public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory
{
    private IBurpExtenderCallbacks m_callbacks;
    private IExtensionHelpers m_helpers;

    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.m_callbacks = callbacks;
        
        // obtain an extension helpers object
        m_helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("AMFSDSer-ngng Extended by Jon Murray 03/2015");
        
        // register ourselves as a message editor tab factory
        AMFTabFactory factory = new AMFTabFactory(m_callbacks, m_helpers);

        callbacks.registerMessageEditorTabFactory(factory);
        
        callbacks.registerContextMenuFactory(new AMFMenu(callbacks, m_helpers));
        
        callbacks.registerHttpListener(new AMFHttpListener(m_helpers));
    }

    //
    // implement IMessageEditorTabFactory
    //
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new AMFDeserializerTab(controller, editable, m_callbacks, m_helpers);
    }

   
}
