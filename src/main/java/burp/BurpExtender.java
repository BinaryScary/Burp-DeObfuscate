package burp;

import java.awt.Component;
import java.io.BufferedReader;
import java.io.StringReader;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public BurpTab tab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName("Burp De-Obfuscate");

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(this);

        tab = new BurpTab(callbacks);
        callbacks.addSuiteTab(this);

        callbacks.printOutput("Burp De-Obfuscate loaded");
    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new DeObfuscateTab(controller, editable);
    }

    @Override
    public String getTabCaption() {return "De-Obfuscator";}

    @Override
    public Component getUiComponent() {return tab.getRootComponent();}


    class DeObfuscateTab implements IMessageEditorTab
    {
        private boolean editable;
        private ITextEditor txtInput;
        private byte[] currentMessage;

        public DeObfuscateTab(IMessageEditorController controller, boolean editable)
        {
            //this.editable = editable;
            this.editable = false;

            // create an instance of Burp's text editor, to display our deserialized data
            txtInput = callbacks.createTextEditor();
            txtInput.setEditable(editable);
        }

        @Override
        public String getTabCaption()
        {
            return "DeObfuscate";
        }

        @Override
        public Component getUiComponent()
        {
            return txtInput.getComponent();
        }

        @Override
        public boolean isEnabled(byte[] content, boolean isRequest)
        {
            return true;
        }

        @Override
        public void setMessage(byte[] content, boolean isRequest)
        {
            if (content == null)
            {
                // clear our display
                txtInput.setText(null);
                txtInput.setEditable(false);
            }
            else
            {
                String mess = helpers.bytesToString(content);
                String lines[] = tab.replacements.split("\\r?\\n");
                String[] split;
                for (String line : lines){
                    split = line.split("\\s+");
                    mess = mess.replace(split[0],split[1]);
                }


                txtInput.setText(helpers.stringToBytes(mess));
                txtInput.setEditable(editable);
            }
            // remember the displayed content
            currentMessage = content;
        }

        @Override
        public byte[] getMessage()
        {
            return currentMessage;
        }

        @Override
        public boolean isModified()
        {
            return txtInput.isTextModified();
        }

        @Override
        public byte[] getSelectedData()
        {
            return txtInput.getSelectedText();
        }
    }
}
