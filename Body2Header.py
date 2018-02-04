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
from java.awt import Insets
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
from javax.swing import JSeparator
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
        callbacks.setExtensionName("Body2Header")
        self._imenu_description = "Add this URL to the scope of Body2Header"
        self._remove_description = "Remove this URL from the scope"
        self._scopes = ArrayList()
        ## User-defined
        self._header_name_default = "X-CSRF-Token"
        self._value_source_regex_default = re.compile("<meta name=\"csrf-token\" content=\"(.*?)\">", re.MULTILINE)
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
        # only process if tools are in the setting
        if not self._checkboxes[toolFlag].isSelected():
            return None

        request_url = self._helpers.analyzeRequest(messageInfo).getUrl()

        if not messageIsRequest:
            body = self._helpers.bytesToString(messageInfo.getResponse()).encode('utf-8')
            for scope in self._scopes:
                if not scope.isMatch(request_url): continue
                csrf_token_b = scope.value_regex.search(body)
                if csrf_token_b != None:
                    scope.stored_value = csrf_token_b.group(1)
                    self.log("New value for {0}: {1}".format(scope.header_name, scope.stored_value))

        # only process requests/responses in the scope
        for scope in self._scopes:
            if not scope.isMatch(request_url): continue
            # Intercept and modify the request
            if messageIsRequest:            
                request = messageInfo.getRequest() 
                requestInfo = self._helpers.analyzeRequest(request)
            
                # update headers
                headers = requestInfo.getHeaders()
                headers = [h for h in headers if not h.startswith(scope.header_name+':')]
                if scope.header_name != "" and scope.stored_value != "":
                    headers.append(scope.header_name + ': ' + scope.stored_value)
                    self.log("{0} was added to the current request.".format(scope.header_name))


                # fetching body to rebubild the request
                body = request[requestInfo.getBodyOffset():]
                updatedRequest = self._helpers.buildHttpMessage(headers, body)
                messageInfo.setRequest(updatedRequest)                



    # Utilities
    def updateTokenSourceRegex(self, e):
        row = self._url_table.getSelectedRow()
        if row == -1:
            return
        self._scopes[row].value_regex = re.compile(self._form_value_regex.getText(), re.MULTILINE)
        self._label_value_regex_now_2.setText(self._scopes[row].value_regex.pattern)
        self.fireTableRowsUpdated(row, row)

        
    def updateHeaderName(self, e):
        row = self._url_table.getSelectedRow()
        if row == -1:
            return
        self._scopes[row].header_name = self._form_header.getText()
        self._label_header_now_2.setText(self._scopes[row].header_name)
        self.fireTableRowsUpdated(row, row)
        
    def addURLDirectly(self, e):
        row = self._scopes.size()
        self._scopes.add(ScopeInfo(self._form_add_url.getText(), self._value_source_regex_default, 
                                   url_regex = re.compile(self._form_add_url.getText(), re.MULTILINE), header_name = self._header_name_default))
        self._form_add_url.setText("")
        self.fireTableRowsInserted(row, row)
    
    def removeFromScope(self, invocation):
        index_to_delete = self._url_table.getSelectedRow()
        self._scopes.pop(index_to_delete)
        self.fireTableRowsDeleted(index_to_delete, index_to_delete)

    def addToScope(self, invocation):
        messagesInfo = self._add_invocation.getSelectedMessages()
        row = self._scopes.size()
        for messageInfo in messagesInfo:
            self._scopes.add(ScopeInfo(self._helpers.analyzeRequest(messageInfo).getUrl(), self._value_source_regex_default, header_name = self._header_name_default))
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
            return self._scopes.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "URL Regex"
        if columnIndex == 1:
            return "Value Regex"
        if columnIndex == 2:
            return "Header Name"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        if columnIndex == 0:
            return self._scopes[rowIndex].url_regex.pattern
        if columnIndex == 1:
            return self._scopes[rowIndex].value_regex.pattern
        if columnIndex == 2:
            return self._scopes[rowIndex].header_name
        return ""

    #
    # implement ITab
    #    

    def getTabCaption(self):
        return "Body2Header"
    
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
        checkboxes_components = {0: dict(zip(range(1,len(self._checkboxes)), self._checkboxes.values()))}

        self._label_value_regex_now_1 = JLabel("(1) Regex for the value to store: ")
        self._label_value_regex_now_2 = JLabel("")
        self._label_value_regex = JLabel("(1) New regex:")
        self._form_value_regex = JTextField("", 64)
        self._button_value_regex = JButton('Update', actionPerformed=self.updateTokenSourceRegex)        
        self._label_header_now_1 = JLabel("(2) Header for sending the value: ")
        self._label_header_now_2 = JLabel("")
        self._label_header = JLabel("(2) New header key: ")
        self._form_header = JTextField("", 64)
        self._button_header = JButton('Update', actionPerformed=self.updateHeaderName)
        self._label_add_url = JLabel("Add this URL: ")
        self._form_add_url = JTextField("", 64)
        self._button_add_url = JButton('Add', actionPerformed=self.addURLDirectly)
                
        ## logate regex settings
        ui_components_for_settings_pane = {
            0: { 0: JLabel("Local Settings:") },
            1: { 0: self._label_value_regex_now_1, 1: self._label_value_regex_now_2 },
            2: { 0: self._label_value_regex, 1: self._form_value_regex, 2: self._button_value_regex},
            3: { 0: self._label_header_now_1, 1: self._label_header_now_2 },
            4: { 0: self._label_header, 1: self._form_header, 2: self._button_header},
            5: { 0: {'item': JSeparator(JSeparator.HORIZONTAL), 'width': 3, }},
            6: { 0: JLabel("General Settings:") },
            7: { 0: self._label_add_url, 1: self._form_add_url, 2: self._button_add_url},
            8: { 0: JLabel("Use this extender in:"), 1: {'item': self.compose_ui(checkboxes_components), 'width': 3} }
        }
        # build a split panel & set UI component
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._splitpane.setResizeWeight(0.85)
        self._splitpane.setLeftComponent(scrollPane)
        self._splitpane.setRightComponent(self.compose_ui(ui_components_for_settings_pane))
        self._callbacks.customizeUiComponent(self._splitpane)
     
    def compose_ui(self, components):
        panel = JPanel() 
        panel.setLayout(GridBagLayout())
        constraints= GridBagConstraints()
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.insets = Insets(2, 1, 2, 1)
        for i in components:
            for j in components[i]:
                constraints.gridy, constraints.gridx = i, j
                constraints.gridwidth = components[i][j]['width'] if type(components[i][j]) == dict and 'width' in components[i][j] else 1
                constraints.gridheight = components[i][j]['height'] if type(components[i][j]) == dict and 'height' in components[i][j] else 1
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
        scopeInfo  = self._extender._scopes.get(row)
        self._extender._label_value_regex_now_2.setText(scopeInfo.value_regex.pattern)
        self._extender._form_value_regex.setText(scopeInfo.value_regex.pattern)
        self._extender._label_header_now_2.setText(scopeInfo.header_name)
        self._extender._form_header.setText(scopeInfo.header_name)
        
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
    def __init__(self, url, value_regex, url_regex=None, header_name=""):
        self.url = url
        self.header_name = header_name
        self.value_regex = value_regex
        self.stored_value = ""
        parsed_url = urlparse.urlparse(str(url))
        if url_regex == None:
            self.url_regex = re.compile("^{0}://{1}{2}.*".format(parsed_url.scheme, parsed_url.netloc, parsed_url.path), re.MULTILINE)
        else:
            self.url_regex = urL_regex
    def isMatch(self, url):
        return self.url_regex.search(str(url)) != None
