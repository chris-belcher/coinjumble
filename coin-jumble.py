
'''
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''


import sys, base64, textwrap, re, datetime

from decimal import Decimal

from PyQt4 import QtCore
from PyQt4.QtGui import *

from bitcoin import *

#https://gist.github.com/e000/869791
import socks
from socksipyhandler import SocksiPyHandler

#TODO get all the url lookups out of the GUI thread, make a worker thread that waits on a queue and executes a 
# function pointer, so do all your work with lambda functions

#MORE THOUGHTS
# use a new tor circuit for each tx part. i asked on #tor and its pointless for hidden services
# cache invalidated when app closed
# what is the point of ascii armor? really? 
#  answer= checksum, small size since b64, short line width, for larger tx the head/foot organises it i.e. a label
#    for really small tx like on irc you can remove the head/foot
# allow changing width of textwrap in ascii_armor() in settings e.g. 500 for irc
# tx fee label in signoff

def get_network():
    if settingsTab.useTestnetCheckbox.checkState() == QtCore.Qt.Checked:
        return 'testnet'
    else:
        return 'btc'

def get_vbyte():
    if get_network() == 'testnet':
        return 0x6f
    else:
        return 0x00

CACHE_TTL = datetime.timedelta(1) #one day
fetchtx_cache_mem = {}
#TODO tell vbuterin to include network='btc' in fetchtx()
#TODO cache to a file too
#TODO cache unspent() calls too
def blockr_fetchtx_cache(txhash, network='btc'):
    if txhash in fetchtx_cache_mem:
        if datetime.datetime.strptime(fetchtx_cache_mem[txhash]['expire'], '%Y/%m/%d %H:%M:%S') > datetime.datetime.now():
            return fetchtx_cache_mem[txhash]['tx'] #cache valid
        else:
            del fetchtx_cache_mem[txhash] #cache expired
    tx = blockr_fetchtx(txhash, network)
    fetchtx_cache_mem[txhash] = {'tx': tx, 'expire': (datetime.datetime.now() + CACHE_TTL).strftime('%Y/%m/%d %H:%M:%S')}
    return tx

#TODO line breaks could be a cross-platform problem... test
BITCOIN_ASCII_ARMOR_HEADER = '-----BEGIN BITCOIN RAW TRANSACTION-----'
BITCOIN_ASCII_ARMOR_FOOTER = '-----END BITCOIN RAW TRANSACTION-----'
TESTNET_ASCII_ARMOR_HEADER = '-----BEGIN TESTNET BITCOIN RAW TRANSACTION-----'
TESTNET_ASCII_ARMOR_FOOTER = '-----END TESTNET BITCOIN RAW TRANSACTION-----'

def get_ascii_head_foot(network):
    head = BITCOIN_ASCII_ARMOR_HEADER
    foot = BITCOIN_ASCII_ARMOR_FOOTER
    if network == 'testnet':
        head = TESTNET_ASCII_ARMOR_HEADER
        foot = TESTNET_ASCII_ARMOR_FOOTER
    return head, foot

def ascii_armor_tx_ex(tx, network, lineWidth):
    txb = tx.decode('hex')
    b64tx = base64.b64encode(txb + bin_dbl_sha256(txb)[:4])
    b64wrapped = textwrap.fill(b64tx, lineWidth)
    head, foot = get_ascii_head_foot(network)
    return head + '\n' + b64wrapped + '\n' + foot

def ascii_armor_tx(tx):
    return ascii_armor_tx_ex(tx, get_network(), settingsTab.asciiArmorLengthEdit.value())

#TypeError for a bad base64 bit (char not in charset, say)
#raises TypeError if somethings wrong
def unascii_armor_tx_ex(armor, network):
     armor = textwrap.dedent(armor).strip()
     head, foot = get_ascii_head_foot(network)
     if not armor.startswith(head + '\n') or \
         not armor.endswith('\n' + foot):
         raise TypeError('Bad header/footer lines. Are you on the right network? (testnet / mainnet)')
     armor = armor[len(head)+1:] #strip header
     armor = armor[:-len(foot)-1]
     b64_payload = ''.join(armor.split('\n'))
     payload = base64.b64decode(b64_payload)
     tx = payload[:-4]
     checksum = bin_dbl_sha256(tx)[:4]
     p_checksum = payload[-4:]
     if checksum != p_checksum:
         raise TypeError('Bad checksum')
     return tx.encode('hex')

def unascii_armor_tx(armor):
    return unascii_armor_tx_ex(armor, get_network())

def unascii_armor_tx_gui(parent, armor):
    try:
        if re.match('^[0-9a-fA-F]*$', armor):
            return armor
        else:
            return unascii_armor_tx(armor)
    except TypeError as e:
        QMessageBox.critical(parent, 'Error', str(e))
        return None

class ListUnspentCoinsTab(QScrollArea):
    def __init__(self):
        super(ListUnspentCoinsTab, self).__init__()
        self.initUI()

#list of a few utxo addresses to try
#1G6sQHBvKobCuCcF8z8ZnYHQUqDyHaqDzy - 1 utxo
#1PYcCM1TgkX995oqEFEHLa6oMJjTKZUdM3 - 3 utxo
#3M8XGFBKwkf7miBzpkU3x2DoWwAVrD1mhk - 55 utxo, the coinjoin bounty address

    def initUI(self): #TODO have a look at using QFormLayout here
        listUnspentTab = QWidget()
        self.setWidget(listUnspentTab)
        self.setWidgetResizable(True)
        self.grid = QGridLayout()
        listUnspentTab.setLayout(self.grid)
        self.grid.setSpacing(10)
        self.grid.addWidget(QLabel('Address :'), 1, 0)
        self.addressInputEdit = QLineEdit()
        self.grid.addWidget(self.addressInputEdit, 1, 1)
        listCoinsButton = QPushButton("List Unspent Coins")
        listCoinsButton.clicked.connect(self.clickedListCoinsButton)
        self.grid.addWidget(listCoinsButton, 1, 2)
        self.unspentCoinDisplayList = [] #TODO needs some kind of scrollbar in case theres a huge amount of utxo

    def clickedListCoinsButton(self, checked):
        for ucdl in self.unspentCoinDisplayList:
            for wid in ucdl:
                self.grid.removeWidget(wid)
                wid.hide()
        self.unspentCoinDisplayList = []
        #TODO check for well-formed address, check if its p2sh and explain this program cant do that yet
        #TODO suggest to vbuterin that b58check_to_bin() raise another exception instead of Assertion since its not so great to catch
        utxos = blockr_unspent(str(self.addressInputEdit.text()), get_network())
        print(str(len(utxos)) + ' found utxo')
        for utxo in utxos: #TODO value needs to go in a QLineEdit so it can be copypasted away
            unspentCoinDisplay = ( #not so urgent though since most people will be coinjoining round numbers
                QLabel('Value: ' + str(Decimal(utxo['value'])/Decimal(1e8)) + 'btc'),
                #TODO create subclass of QLineEdit that isnt editable and highlights it when you click
                #plus right-click option to copy, and responds to ctrl+c
                QLineEdit(utxo['output'])
            )
            unspentCoinDisplay[1].setReadOnly(True)
            self.unspentCoinDisplayList.append(unspentCoinDisplay)
            for i in range(2):
                self.grid.addWidget(unspentCoinDisplay[i], len(self.unspentCoinDisplayList)+1, i)

#TODO this maybe needs a way to edit a tx, so if you make a mistake you dont have to start
# over again copypasting in utxos
class CreateTransactionPartTab(QWidget):
    def __init__(self):
        super(CreateTransactionPartTab, self).__init__()
        self.initUI()

    def initUI(self):
        self.grid = QGridLayout()
        self.setLayout(self.grid)
        self.grid.setSpacing(10)

        columns = [0, 2, 3]
        charCounts = [66, 36, 7] #expected number of chars in that QLineEdit
        dummy = QLineEdit()
        for c, cc in zip(columns, charCounts):
            self.grid.setColumnMinimumWidth(c, dummy.fontMetrics().boundingRect('U'*cc).width())
        #self.grid.setColumnMinimumWidth(0, 480)
        #self.grid.setColumnMinimumWidth(2, 270)
        #self.grid.setColumnMinimumWidth(3, 10)

        #USE QSPLITTER HERE ?

        self.txEdit = QPlainTextEdit(self)
        self.txEdit.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.grid.addWidget(self.txEdit, 0, 0, 1, 4)

        createTxPartButton = QPushButton('Create Tx Part', self)
        createTxPartButton.clicked.connect(self.clickedCreateTxPartButton)
        self.grid.addWidget(createTxPartButton, 1, 0, 1, 4)

        addUnspentCoinButton = QPushButton('Add Unspent Coin', self)
        addUnspentCoinButton.clicked.connect(self.clickedAddUnspentCoinButton)
        self.grid.addWidget(addUnspentCoinButton, 2, 0, 1, 2)

        addOutputButton = QPushButton('Add Output', self)
        addOutputButton.clicked.connect(self.clickedAddOutputButton)
        self.grid.addWidget(addOutputButton, 2, 2, 1, 2)

        self.grid.addWidget(QLabel('Unspent Coins'), 3, 0, 1, 2, QtCore.Qt.AlignHCenter)
        self.grid.addWidget(QLabel('Output Address'), 3, 2, 1, 1, QtCore.Qt.AlignHCenter)
        self.grid.addWidget(QLabel('Output Value/btc'), 3, 3, 1, 1, QtCore.Qt.AlignHCenter)

        self.unspentCoinEditList = []
        self.outputEditList = []

        #for i in range(self.grid.columnCount()):
        #    print('i, mWidth, stretch = ' + str(i) + ', ' + 
        #        str(self.grid.columnMinimumWidth(i)) + ', ' + str(self.grid.columnStretch(i)))


    def clickedCreateTxPartButton(self, checked):
        utxo = []
        for ucel in self.unspentCoinEditList:
            newutxo = str(ucel.text()).strip()
            if newutxo != '':
                utxo.append({'output': newutxo})
            self.grid.removeWidget(ucel)
            ucel.hide()
        self.unspentCoinEditList = []
        outs = [] #TODO verify formats of all these inputs
        for oel in self.outputEditList:
            addr = str(oel[0].text()).strip()
            #use Decimal for accounting numbers
            value = int( Decimal(str(oel[1].text()).strip()) * Decimal(1e8) )
            if addr != '' and value != '':
                outs.append( {'address': addr, 'value': value} )
            for wid in oel:
                self.grid.removeWidget(wid)
                wid.hide()
        self.outputEditList = []
        self.txEdit.setPlainText(ascii_armor_tx(mktx(utxo, outs)))
        self.txEdit.selectAll()

    def clickedAddUnspentCoinButton(self, checked):
        new_utxoEdit = QLineEdit()
        self.grid.addWidget(new_utxoEdit, len(self.unspentCoinEditList) + 4, 0, 1, 2)
        self.unspentCoinEditList.append(new_utxoEdit)

    def clickedAddOutputButton(self, checked):
        new_output = (QLineEdit(), QLineEdit())
        self.grid.addWidget(new_output[0], len(self.outputEditList) + 4, 2, 1, 1)
        self.grid.addWidget(new_output[1], len(self.outputEditList) + 4, 3, 1, 1)
        self.outputEditList.append(new_output)

class CombineTransactionPartsTab(QWidget):
    def __init__(self):
        super(CombineTransactionPartsTab, self).__init__()
        self.initUI()

    def initUI(self):
        grid = QGridLayout()
        self.setLayout(grid)
        grid.setSpacing(10)

        self.txEdit = QPlainTextEdit(self)
        self.txEdit.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        grid.addWidget(QLabel('Tx Parts'), 0, 0)
        grid.addWidget(self.txEdit, 0, 1)

        combineTxPartsButton = QPushButton('Combine Transaction Parts', self)
        combineTxPartsButton.clicked.connect(self.clickedCombineTxPartsButton)
        grid.addWidget(combineTxPartsButton, 1, 1)

        self.resultEdit = QPlainTextEdit(self) #TODO make this one uneditable maybe?
        self.resultEdit.setLineWrapMode(QPlainTextEdit.WidgetWidth) #and select-all when you click?
        grid.addWidget(QLabel('Result'), 2, 0)
        grid.addWidget(self.resultEdit, 2, 1)

    def clickedCombineTxPartsButton(self, checked):
        head, foot = get_ascii_head_foot(get_network())
        matches = re.finditer('(' + head + '[0-9A-Za-z+/=\n]*' + foot + ')',
            str(self.txEdit.toPlainText()), re.MULTILINE | re.DOTALL)
        if matches == None:
            print('no header/footers found')
            return
        result = None
        for m in matches:
            tx = deserialize(unascii_armor_tx(m.group(1)))
            if result == None:
                result = tx
            else:
                result['ins'] = result['ins'] + tx['ins']
                result['outs'] = result['outs'] + tx['outs']
        self.resultEdit.setPlainText(ascii_armor_tx(serialize(result)))
        self.resultEdit.selectAll()
        self.txEdit.setPlainText('')

class QLabelSelectable(QLabel):
    def __init__(self, *args, **kwargs):
        super(QLabelSelectable, self).__init__(*args, **kwargs)
        self.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

#TODO somewhere do checking that sum of outputs <= sum of inputs
# and other simple checks that a node or client would do
# then again, the site connected to by pushtx() will do these checks
class SignOffTab(QScrollArea):
    def __init__(self):
        super(SignOffTab, self).__init__()
        self.initUI()

    def initUI(self):
        signOffTab = QWidget()
        self.setWidget(signOffTab)
        self.setWidgetResizable(True)

        self.grid = QGridLayout()
        signOffTab.setLayout(self.grid)
        self.grid.setSpacing(10)

        self.txEdit = QPlainTextEdit(self)
        self.txEdit.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.grid.addWidget(self.txEdit, 0, 0, 1, 4)

        viewTxButton = QPushButton('View Transaction', self)
        viewTxButton.clicked.connect(self.clickedViewTxButton)
        self.grid.addWidget(viewTxButton, 1, 0, 1, 4)

        self.unspentCoinsLabel = QLabel('<u>Unspent Coins</u>')
        self.outputsLabel = QLabel('<u>Outputs</u>')
        self.grid.addWidget(self.unspentCoinsLabel, 2, 1, 1, 1, QtCore.Qt.AlignHCenter)
        self.grid.addWidget(self.outputsLabel, 2, 3, 1, 1, QtCore.Qt.AlignHCenter)
        #TODO QLabel somewhere with sum of inputs / outputs / fee

        self.broadcastTxButton = QPushButton('Broadcast Transaction', self)
        self.broadcastTxButton.setEnabled(False)
        self.broadcastTxButton.clicked.connect(self.clickedBroadcastTxButton)
        self.grid.addWidget(self.broadcastTxButton, 3, 0, 1, 4)

        self.unspentCoinsWidgetList = []
        self.outputsWidgetList = []
        self.signedCount = 0

    def clickedViewTxButton(self, checked):
        tx = unascii_armor_tx_gui(self, str(self.txEdit.toPlainText()))
        if tx == None:
            return
        self.txEdit.setPlainText(ascii_armor_tx(tx))
        txd = deserialize(tx)

        for ucwl in self.unspentCoinsWidgetList:
            for wid in ucwl:
                self.grid.removeWidget(wid)
                wid.hide()
        self.unspentCoinsWidgetList = []
        for owl in self.outputsWidgetList:
            self.grid.removeWidget(owl)
            owl.hide()
        self.outputsWidgetList = []
        self.grid.removeWidget(self.broadcastTxButton)
        self.signedCount = 0
        self.unspentCount = 0

        self.inputSum = 0 #in satoshi
        self.outputSum = 0

        for index, inputs in enumerate(txd['ins']):
            #print('fetchtx ' + inputs['outpoint']['hash'])

            #TODO catch the Exception if these lookups fail, maybe display the tx anyway
            # with (lookup err) where value and addr should be
            #on second thoughts, the signing depends on this so lookup failure should be
            # a proper error that you need a popup box asking if your internet works
            ftx = blockr_fetchtx_cache(inputs['outpoint']['hash'], get_network())
            scr_val = deserialize(ftx)['outs'][inputs['outpoint']['index']]
            self.inputSum += scr_val['value']
            buttonText = 'Unsigned'
            if inputs['script'] != '':
                if verify_tx_input(tx, index, scr_val['script'], *deserialize_script(inputs['script'])):
                    buttonText = 'Signed'
                    self.signedCount += 1
                else:
                    buttonText = 'Failed'
            signButton = QPushButton(buttonText)
            signButton.setEnabled(buttonText != 'Signed')
            signButton.clicked.connect(self.clickedSignButton)

            utxo = inputs['outpoint']['hash'] + ':' + str(inputs['outpoint']['index'])
            addr = script_to_address(scr_val['script'], get_vbyte())
            utxoList = blockr_unspent(addr, get_network())
            utxoList = [u['output'] for u in utxoList]
            spentStatus = 'Unspent' if utxo in utxoList else '<font color="red">Spent</font>'
            if spentStatus == 'Unspent':
                self.unspentCount += 1

            unspentCoinsWidgets = (
                signButton,
                QLabelSelectable('<b>' + utxo +
                    '</b> (' + str(Decimal(scr_val['value'])/Decimal(1e8)) + 'btc)'),
                QLabelSelectable(addr + ' <b>' + spentStatus + '</b>')
            )
            self.grid.addWidget(unspentCoinsWidgets[0], len(self.unspentCoinsWidgetList)*2 + 3, 0)
            self.grid.addWidget(unspentCoinsWidgets[1], len(self.unspentCoinsWidgetList)*2 + 3, 1)
            self.grid.addWidget(unspentCoinsWidgets[2], len(self.unspentCoinsWidgetList)*2 + 4, 1, QtCore.Qt.AlignHCenter)
            self.unspentCoinsWidgetList.append(unspentCoinsWidgets)
        for o in txd['outs']:
            outputWidgets = QLabelSelectable('<b>' + script_to_address(o['script'], get_vbyte()) +
                '</b> (' + str(Decimal(o['value'])/Decimal(1e8)) + 'btc)')
            self.outputSum += o['value']
            self.grid.addWidget(outputWidgets, len(self.outputsWidgetList)*2 + 3, 3)
            self.outputsWidgetList.append(outputWidgets)

        self.grid.addWidget(QLabel('=====>'), 3, 2, 1, 1, QtCore.Qt.AlignHCenter)

        self.unspentCoinsLabel.setText('<u>Unspent Coins</u> Total value: ' +
            str(Decimal(self.inputSum)/Decimal(1e8)) + 'btc')
        self.outputsLabel.setText('<u>Outputs</u> Total value: ' +
            str(Decimal(self.outputSum)/Decimal(1e8)) + 'btc')

        broadcastRow = max(len(self.unspentCoinsWidgetList), len(self.outputsWidgetList))*2 + 5
        self.grid.addWidget(self.broadcastTxButton, broadcastRow, 0, 1, 4)
        canBroadcast = self.signedCount == len(self.unspentCoinsWidgetList) and \
            self.unspentCount == len(self.unspentCoinsWidgetList)
        self.broadcastTxButton.setEnabled(canBroadcast)

    def clickedSignButton(self, checked):
        index = -1
        for i, ucwl in enumerate(self.unspentCoinsWidgetList):
            if ucwl[0] == self.sender():
                index = i
                break
        assert index != -1
        tx = unascii_armor_tx_gui(self, str(self.txEdit.toPlainText()))
        if tx == None:
            return
        utxo = str(re.search('<b>([0-9a-fA-F]*:[0-9]*)</b>', self.unspentCoinsWidgetList[index][1].text()).group(1))
        privkey, ok = QInputDialog.getText(self, 'Sign Transaction', 'Input private key\nFor ' + utxo)
        if not ok:
            return
        #TODO format checking here, put in try: and show error
        newtx = sign(tx, index, str(privkey).strip())
        ftx = blockr_fetchtx_cache(utxo[:64], get_network()) #since we already looked it this is just a cache query
        scr_val = deserialize(ftx)['outs'][int(utxo[65:])]
        scri = deserialize(newtx)['ins'][index]['script']
        buttonText = 'Failed'
        if verify_tx_input(tx, index, scr_val['script'], *deserialize_script(scri)):
            buttonText = 'Signed'
            self.txEdit.setPlainText(ascii_armor_tx(newtx))
            self.txEdit.selectAll()
            self.signedCount += 1
            self.broadcastTxButton.setEnabled(self.signedCount == len(self.unspentCoinsWidgetList))
        self.sender().setText(buttonText)
        self.sender().setEnabled(buttonText != 'Signed')

    def clickedBroadcastTxButton(self, checked):
        tx = unascii_armor_tx_gui(self, str(self.txEdit.toPlainText()))
        if tx == None:
            return
        #TODO its possible for someone to change what's in txEdit and broadcast that, which is bad
        print('txhash = ' + tx)
        reply = QMessageBox.question(self, 'Broadcast Transaction', 'Are you sure you want to broadcast?\n\n' +
             'Miner fees: ' + str(Decimal(self.inputSum - self.outputSum)/Decimal(1e8)) + 'btc\n\n' +
             'Sum of Unspent Coins: ' + str(Decimal(self.inputSum)/Decimal(1e8)) + 'btc\nSum of Outputs: ' +
             str(Decimal(self.outputSum)/Decimal(1e8)) + 'btc', QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return
        ret = blockr_pushtx(tx, get_network()) #TODO tell vbuterin to have a single pushtx() function that could use many services
        QMessageBox.information(self, 'Push Transaction', str(ret)) #blockr_pushtx() eligis_pushtx()
        print(ret)

#TODO change denominations, mbtc, ubtc, bits
# make a satoshi_to_unit() and unit_to_satoshi()
class SettingsTab(QWidget):
    def __init__(self):
        super(SettingsTab, self).__init__()
        self.initUI()

    def initUI(self):
        QLabel('<b>Proxy Server</b> - For example using tor', self).move(550, 30)
        QLabel('Host', self).move(560, 64)
        self.proxyHostEdit = QLineEdit('localhost', self)
        self.proxyHostEdit.move(590, 60)
        QLabel('Port', self).move(560, 104)
        self.proxyPortEdit = QSpinBox(self)
        self.proxyPortEdit.move(590, 100)
        self.proxyPortEdit.setRange(0, 65535)
        self.proxyPortEdit.setValue(9150)
        useProxyCheckbox = QCheckBox('Use Socks5 Proxy', self)
        useProxyCheckbox.setCheckState(False)
        useProxyCheckbox.move(590, 135)
        useProxyCheckbox.stateChanged.connect(self.useProxyCheckboxChanged)

        self.useTestnetCheckbox = QCheckBox('Testnet', self)
        self.useTestnetCheckbox.setCheckState(False)
        self.useTestnetCheckbox.move(30, 120)
        self.useTestnetCheckbox.stateChanged.connect(self.useTestnetCheckboxChanged)

        clearFetchTxCache = QPushButton('Clear FetchTx() Cache', self)
        clearFetchTxCache.move(300, 50)
        clearFetchTxCache.clicked.connect(lambda checked: fetchtx_cache_mem.clear())

        QLabel('Ascii Armor Line Length', self).move(30, 50)
        self.asciiArmorLengthEdit = QSpinBox(self)
        self.asciiArmorLengthEdit.move(30, 70)
        self.asciiArmorLengthEdit.setRange(1, 2048)
        self.asciiArmorLengthEdit.setValue(64)

        aboutButton = QPushButton('About', self)
        aboutButton.move(200, 100)
        aboutButton.clicked.connect(lambda checked: QMessageBox.about(self, 'About',
            'Coin Jumble coded by Belcher\nA small application to make it easier to do' +
            ' CoinJoin transactions.\nIf my program is useful to you, I take donations at' +
            ' 1DnGHcMAJBtPXSMuQxiXDg93TXRwd9fGzD'))

        aboutQtButton = QPushButton("About Qt", self)
        #aboutQtButton.resize(aboutQtButton.sizeHint())
        aboutQtButton.move(200, 50)
        aboutQtButton.clicked.connect(lambda checked: QMessageBox.aboutQt(self, 'About Qt'))

    def useProxyCheckboxChanged(self, state):
        self.proxyHostEdit.setEnabled(state == QtCore.Qt.Unchecked)
        self.proxyPortEdit.setEnabled(state == QtCore.Qt.Unchecked)
        if state == QtCore.Qt.Checked:
            host = str(self.proxyHostEdit.text())
            port = self.proxyPortEdit.value()
            bci_set_proxy(SocksiPyHandler(socks.PROXY_TYPE_SOCKS5, host, port))
        else:
            bci_set_proxy(None)

    def useTestnetCheckboxChanged(self, checked):
        add = ''
        if checked:
            add = ' - Testnet'
        w.setWindowTitle(appWindowTitle + add)

if len(sys.argv) == 2:
    sys.exit(0)

app = QApplication(sys.argv)
w = QMainWindow()
tabWidget = QTabWidget(w)

tabWidget.addTab(ListUnspentCoinsTab(), "List Unspent Coins")
tabWidget.addTab(CreateTransactionPartTab(), "Create Transaction Part")
tabWidget.addTab(CombineTransactionPartsTab(), "Combine Transaction Parts")

#should it contain the word 'verify' ? because this tab is probably the only one you can view and unarmor/deserialize tx
# but if thats the case it should have the word 'view' instead? or 'un-armor' or 'deserialize', the last two words being too long
tabWidget.addTab(SignOffTab(), "Sign Off Transaction")

settingsTab = SettingsTab()
tabWidget.addTab(settingsTab, "Settings")
#TODO proxy (for tor), with a message that if you dont want your ip linked with those unspent coins or pushtx()
#  honestly though (the message should say) odds are your ip IS linked with the unspent coins unless you're really careful
# combobox choosing bc.i or blockr or both randomly, combobox choosing where to pushtx()
# testnet, about button/message box
# maybe a thing that generates testnet privkeys and addresses so people can play around
#QMessageBox has about() and aboutQt() which is nice

#have a py2exe version
#but also mention you can easily run the single file python script on tails

#TODO w.setStatusBar() is maybe useful, for when stuff is downloading
w.resize(700, 300)
#w.move(300, 300)
appWindowTitle = 'Coin Jumble GUI'
w.setWindowTitle(appWindowTitle)
w.setCentralWidget(tabWidget)
w.show()

sys.exit(app.exec_())
