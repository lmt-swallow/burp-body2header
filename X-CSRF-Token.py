import re
from datetime import datetime
import urllib
import urlparse

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IContextMenuFactory

from java.awt import Component
from java.awt import Point
from java.awt import GridBagLayout, GridBagConstraints
from java.awt.event import MouseAdapter, MouseEvent
from java.util import ArrayList
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from javax.swing import JTable;
from javax.swing import JPanel
from javax.swing import JMenuItem
from javax.swing import JPopupMenu
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing.table import AbstractTableModel;


class BurpExtender(IBurpExtender, ITab, IHttpListener, AbstractTableModel, IContextMenuFactory):
    
    #
    # implement IBurpExtender
    #
    
    def registerExtenderCallbacks(self, callbacks):
        # set default values
        ## Pre-defined
        callbacks.setExtensionName("X-CSRF-Token")
        self._imenu_description = "Add this URL to the scope of X-CSRF-Token"
        self._remove_description = "Remove this URL from the scope"
        self._scope = ArrayList()
        ## User-defined
        self._header_name = "X-CSRF-Token"
        self._CSRF_source_regex = re.compile("<meta name=\"csrf-token\" content=\"(.*?)\">", re.MULTILINE)
        self._csrf_token = ""



        # store callbacks set an alias for stdout and helpers
        self._callbacks = callbacks
        self._out = callbacks.getStdout()
        self._helpers = callbacks.getHelpers()

        # initialize GUI
        callbacks.registerContextMenuFactory(self)
        self.initializeGUI()
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

      
    def log(self, message):
        self._out.write("[{0}] {1}\n".format(datetime.now().isoformat(),message))        
    #
    # implement IHttpListener
    #
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests/responses in the scope
        if not self.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            return

        # only process if tools are in the setting
        if not self._checkboxes[toolFlag].isSelected():
            return None

        # Intercept and modify the request
        if messageIsRequest:            
            request = messageInfo.getRequest() 
            requestInfo = self._helpers.analyzeRequest(request)
            
            # update headers
            headers = requestInfo.getHeaders()
            headers = [h for h in headers if not h.startswith(self._header_name+':')]
            headers.append(self._header_name + ': ' + self._csrf_token)

            # fetching body to rebubild the request
            body = request[requestInfo.getBodyOffset():]
            updatedRequest = self._helpers.buildHttpMessage(headers, body)
            messageInfo.setRequest(updatedRequest)

            self.log("{0} was added to the current request.".format(self._header_name))

        # Find a CSRF Tokens with the given regex
        else:
            body = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            csrf_token_b = self._CSRF_source_regex.search(body)
            if csrf_token_b != None:
                self._csrf_token = csrf_token_b.group(1)
                self.log("New token: {0}".format(self._csrf_token))

    # Utilities
    def updateTokenSourceRegex(self, e): 
        self._CSRF_source_regex = re.compile(self._form_CSRF_regex.getText(), re.MULTILINE)
        self._label_CSRF_regex_now_2.setText(self._CSRF_source_regex.pattern)
        
    def updateHeaderName(self, e):
        self._header_name = self._form_CSRF_header.getText()
        self._label_CSRF_header_now_2.setText(self._header_name)

    def addURLDirectly(self, e):
        row = self._scope.size()
        self._scope.add(ScopeInfo(self._form_add_url.getText(),
                                  re.compile(self._form_add_url.getText(), re.MULTILINE)))
        self._form_add_url.setText("")
        self.fireTableRowsInserted(row, row)

    def isInScope(self, url):
        for inscope in self._scope:
            if inscope.regex.search(str(url)):
                return True
        return False
    
    def removeFromScope(self, invocation):
        index_to_delete = self._url_table.getSelectedRow()
        self._scope.pop(index_to_delete)
        self.fireTableRowsDeleted(index_to_delete, index_to_delete)

    def addToScope(self, invocation):
        messagesInfo = self._add_invocation.getSelectedMessages()
        row = self._scope.size()
        for messageInfo in messagesInfo:
            self._scope.add(ScopeInfo(self._helpers.analyzeRequest(messageInfo).getUrl()))
        self.fireTableRowsInserted(row, row)

    #
    # implement IContextMenuFactory
    #

    def createMenuItems(self, invocation):
        self._add_invocation = invocation
        self._imenu = JMenuItem(self._imenu_description, actionPerformed=self.addToScope)
        return [self._imenu]

    #
    # extend AbstractTableModel
    #
    
    def getRowCount(self):
        try:
            return self._scope.size()
        except:
            return 0

    def getColumnCount(self):
        return 1

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL Regex"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if columnIndex == 0:
            return self._scope.get(rowIndex).regex.pattern
        return ""

    #
    # implement ITab
    #    

    def getTabCaption(self):
        return "X-CSRF-Token"
    
    def getUiComponent(self):
        return self._splitpane

    #
    # GUI settings
    #

    def initializeGUI(self):
        # table panel of scope entries
        self._url_table = Table(self)
        table_popup = JPopupMenu();
        remove_item_menu = JMenuItem(self._remove_description, actionPerformed=self.removeFromScope)
        table_popup.add(remove_item_menu)
        self._url_table.setComponentPopupMenu(table_popup)
        self._url_table.addMouseListener(TableMouseListener(self._url_table))
        scrollPane = JScrollPane(self._url_table)

        # setting panel              

        ##  locate checkboxes
        ### for constants, see: https://portswigger.net/burp/extender/api/constant-values.html#burp.IBurpExtenderCallbacks.TOOL_PROXY          
        self._checkboxes = {
            2:    JCheckBox('Target'),
            4:    JCheckBox('Proxy'),
            8:    JCheckBox('Spider'),
            16:   JCheckBox('Scanner'),
            32:   JCheckBox('Intruder'),            
            64:   JCheckBox('Repeater'),
            128:  JCheckBox('Sequencer'),
            1024: JCheckBox('Extender')
        }
        self._label_CSRF_regex_now_1 = JLabel("(1) Regex For Searching CSRF Token: ")
        self._label_CSRF_regex_now_2 = JLabel(self._CSRF_source_regex.pattern)
        self._label_CSRF_regex = JLabel("(1) New Regex:")
        self._form_CSRF_regex = JTextField("<meta name=\"csrf-token\" content=\"(.*)\">",64)
        self._button_CSRF_regex = JButton('Update', actionPerformed=self.updateTokenSourceRegex)        
        self._label_CSRF_header_now_1 = JLabel("(2) Header for CSRF Token: ")
        self._label_CSRF_header_now_2 = JLabel(self._header_name)        
        self._label_CSRF_header = JLabel("(2) New Header Name: ")
        self._form_CSRF_header = JTextField(self._header_name,64)
        self._button_CSRF_header = JButton('Update', actionPerformed=self.updateHeaderName)
        self._label_add_url = JLabel("(3) Add This URL: ")
        self._form_add_url = JTextField("", 64)
        self._button_add_url = JButton('Add', actionPerformed=self.addURLDirectly)

        checkboxes_components = {0: dict(zip(range(0,len(self._checkboxes)), self._checkboxes.values()))}
        ## logate regex settings
        ui_components_for_settings_pane = {
            0: { 0: self._label_CSRF_regex_now_1, 1: self._label_CSRF_regex_now_2 },
            1: { 0: self._label_CSRF_regex, 1: self._form_CSRF_regex, 2: self._button_CSRF_regex},
            2: { 0: self._label_CSRF_header_now_1, 1: self._label_CSRF_header_now_2 },
            3: { 0: self._label_CSRF_header, 1: self._form_CSRF_header, 2: self._button_CSRF_header},
            4: { 0: self._label_add_url, 1: self._form_add_url, 2: self._button_add_url},
            5: { 0: {'item': self.compose_ui(checkboxes_components), 'width': 3} }
        }
        # build a split panel & set UI component
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setResizeWeight(0.8)
        self._splitpane.setLeftComponent(scrollPane)
        self._splitpane.setRightComponent(self.compose_ui(ui_components_for_settings_pane))
        self._callbacks.customizeUiComponent(self._splitpane)
     
    def compose_ui(self, components):
        panel = JPanel() 
        panel.setLayout(GridBagLayout())
        constraints= GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        for i in components:
            for j in components[i]:
                constraints.gridy, constraints.gridx = i, j
                constraints.gridwidth = components[i][j]['width'] if type(components[i][j]) == dict and 'width' in components[i][j] else 1
                item = components[i][j]['item'] if type(components[i][j]) == dict and 'item' in components[i][j] else components[i][j]
                panel.add(item, constraints)
        return panel    


#
# Wrappers for JTable
#

class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)    
    def changeSelection(self, row, col, toggle, extend):    
        ScopeInfo = self._extender._scope.get(row)
        JTable.changeSelection(self, row, col, toggle, extend)

class TableMouseListener(MouseAdapter):
    def __init__(self, table):
        self._table = table
    def mousePressed(self, event):
        point = event.getPoint()
        currentRow = self._table.rowAtPoint(point)
        self._table.setRowSelectionInterval(currentRow, currentRow)
    
#
# Scope definition (to be extended)
#

class ScopeInfo:
    def __init__(self, url, regex=None):
        self.url = url
        parsed_url = urlparse.urlparse(str(url))
        if regex == None:
            self.regex = re.compile("^{0}://{1}{2}.*".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path), re.MULTILINE)
        else:
            self.regex = regex
