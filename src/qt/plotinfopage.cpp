// Copyright (c) 2011-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <qt/plotinfopage.h>
#include <qt/forms/ui_plotinfopage.h>

#include <qt/bitcoinunits.h>
#include <qt/clientmodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/transactionfilterproxy.h>
#include <qt/transactiontablemodel.h>
#include <qt/walletmodel.h>
#include <qt/forms/ui_plotinfopage.h>
#include <QLineEdit>
#include <QMessageBox>
#include <QPair>

#include <interfaces/wallet.h>
#include <key_io.h>
#include <outputtype.h>

#include <optional.h>
#include <validation.h> // cs_main
#include <univalue.h>
#include <actiondb.h>
#include <rpc/passphrase.h>
#include <rpc/protocol.h>
#include <wallet/wallet.h>
#include "txfeemodifier.h"

Q_DECLARE_METATYPE(interfaces::WalletBalances)

PlotInfoPage::PlotInfoPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PlotInfoPage),
    _walletModel(nullptr)
{
    ui->setupUi(this);

    ui->gbNewAddress->hide();
    ui->plotIdLabel->hide();
    ui->ebPlotId->hide();

    connect(ui->btnNewAddress, SIGNAL(clicked()), SLOT(onNewPlotIdClicked()));
}

PlotInfoPage::~PlotInfoPage()
{
    delete ui;
}


void PlotInfoPage::setWalletModel(WalletModel *walletModel) {
  _walletModel = walletModel;
  updateData();
}

void PlotInfoPage::updateData() {
  auto& wallet = _walletModel->wallet();
  if (wallet.isLocked()) {
      return;
  }

  LOCK(cs_main);

  auto defaultAddress = getDefaultMinerAddress();
  if(defaultAddress) {
    CTxDestination dest = GetDestinationForKey(defaultAddress.get(), OutputType::LEGACY);
    auto address = QString::fromStdString(EncodeDestination(dest));
    auto plotId = QString("%0").arg(defaultAddress->GetID().GetPlotID());

    ui->ebMinerAddress->setText(address);
    //ui->ebPlotId->setText(plotId);
  }
}

Optional<CPubKey> PlotInfoPage::getDefaultMinerAddress()
{
  auto& wallet = _walletModel->wallet();
  std::vector<std::pair<int64_t, CKeyID>> vKeyBirth = getWalletKeys();
  std::vector<std::pair<int64_t, CKeyID>>::const_iterator firstItem = vKeyBirth.begin();
  CKey key;
  std::string label = "miner";
  if (firstItem != vKeyBirth.end()) {
    const CKeyID& keyid = firstItem->second;
    if (wallet.getPrivKey(keyid, key)) {
      auto pubkey = key.GetPubKey();
      wallet.learnRelatedScripts(pubkey, OutputType::P2SH_SEGWIT);

      for (const auto& dest : GetAllDestinationsForKey(pubkey)) {
        if (wallet.hasAddress(dest) == 0) {
          wallet.setAddressBook(dest, label, "receive");
        }
      }

      return boost::make_optional(pubkey);
    }
  }

  return nullopt;
}

void PlotInfoPage::onNewPlotIdClicked()
{
  auto passphrase = poc::generatePassphrase();
  auto plotId = QString("%0").arg(poc::GeneratePlotId(passphrase));

  ui->ebNewAddress->setText(QString::fromStdString(passphrase));
  ui->ebNewId->setText(plotId);
  ui->gbNewAddress->show();
}

Optional<CPubKey> PlotInfoPage::getNewMinerAddress()
{
  std::string label = "miner";
  auto& wallet = _walletModel->wallet();
  CPubKey newKey;
  if (!wallet.getKeyFromPool(false, newKey)) {
    return nullopt;
  }

  wallet.learnRelatedScripts(newKey, OutputType::P2SH_SEGWIT);

  for (const auto& dest : GetAllDestinationsForKey(newKey)) {
    if (wallet.hasAddress(dest) == 0) {
      wallet.setAddressBook(dest, label, "receive");
    }
  }
  return boost::make_optional(newKey);
}

std::vector<std::pair<int64_t, CKeyID> > PlotInfoPage::getWalletKeys()
{
  auto& wallet = _walletModel->wallet();
  auto keyBirth = wallet.GetKeyBirthTimes();

  // sort time/key pairs
  std::vector<std::pair<int64_t, CKeyID>> vKeyBirth;
  for (const auto& entry : keyBirth) {
      if (const CKeyID* keyID = boost::get<CKeyID>(&entry.first)) { // set and test
          vKeyBirth.push_back(std::make_pair(entry.second, *keyID));
      }
  }
  keyBirth.clear();
  std::sort(vKeyBirth.begin(), vKeyBirth.end());
  return vKeyBirth;
}

static inline Optional<QPair<PlotInfoPage::AddressInfo, PlotInfoPage::AddressInfo>> getBinding(const CKeyID& from) {
    Optional<QPair<PlotInfoPage::AddressInfo, PlotInfoPage::AddressInfo>> ret;

    LOCK(cs_main);
    auto to = prelationview->To(from);
    if (to == CKeyID()) {
        return ret;
    }

    PlotInfoPage::AddressInfo fromInfo = { EncodeDestination(CTxDestination(from)), from.GetPlotID() };
    PlotInfoPage::AddressInfo toInfo = { EncodeDestination(CTxDestination(to)), to.GetPlotID() };

    auto data = QPair<PlotInfoPage::AddressInfo, PlotInfoPage::AddressInfo>(fromInfo, toInfo);
    return boost::make_optional(data);
}

QString PlotInfoPage::getBindingInfoStr(const QPair<PlotInfoPage::AddressInfo, PlotInfoPage::AddressInfo>& data) {
  auto message = tr("Address \"%1\" binds to \"%2\"")
          .arg(QString("%0").arg(data.first.plotId))
          .arg(QString::fromStdString(data.second.address));
  return message;
}

void PlotInfoPage::on_btnQuery_clicked()
{
  QString address = ui->ebAddrToQuery->text().trimmed();
  if (address.isEmpty()) {
    QMessageBox::warning(this, windowTitle(), tr("Please enter a valid PlotID"), QMessageBox::Ok, QMessageBox::Ok);
    return;
  }
  uint64_t plotid = std::stoull(address.toStdString());
  auto from = CKeyID(plotid);
  auto results = getBinding(from);
  if (!results) {
    QMessageBox::information(this, windowTitle(), tr("No binding found for PlotID: \"%1\"").arg(address), QMessageBox::Ok, QMessageBox::Ok);
    return;
  }

  auto data = results.get();
  auto message = getBindingInfoStr(data);
  QMessageBox::information(this, windowTitle(), message, QMessageBox::Ok, QMessageBox::Ok);
}

void PlotInfoPage::on_btnBind_clicked()
{
    if (!_walletModel || _walletModel->wallet().isLocked()) {
        QMessageBox::warning(this, windowTitle(), tr("Please unlock wallet to continue"), QMessageBox::Ok, QMessageBox::Ok);
        return;
    }
    auto fromMnem = ui->ebMnemonicFrom->text().trimmed().toStdString();
    auto fromAddr = ui->ebAddressFrom->text().trimmed();
    uint64_t plotID = poc::GeneratePlotId(fromMnem);
    auto toAddr = ui->ebAddressTo->text().trimmed();
    CTxDestination toDest = DecodeDestination(toAddr.toStdString());

    if (std::to_string(plotID) != fromAddr.toStdString()) {
      QMessageBox::warning(this, windowTitle(), tr("passphrase and plotid mismatch"), QMessageBox::Ok, QMessageBox::Ok);
      return;
    }
    if (!IsValidDestination(toDest) || toDest.type() != typeid(CKeyID)) {
      QMessageBox::warning(this, windowTitle(), tr("Invalid to address"), QMessageBox::Ok, QMessageBox::Ok);
      return;
    }

    auto fromPid = CKeyID(plotID);
    auto results = getBinding(fromPid);
    if (results) {
      int ret = QMessageBox::warning(this, windowTitle(), tr("This PlotID already binds to an address, are you sure to continue?"), QMessageBox::Yes, QMessageBox::Cancel);
      if (ret != QMessageBox::Yes) {
        return;
      }
    }

    auto lock = _walletModel->requestUnlock();
    if (!lock.isValid()) {
      QMessageBox::warning(this, windowTitle(), tr("Failed to unlock wallet"), QMessageBox::Ok, QMessageBox::Ok);
      return;
    }

    int ret = QMessageBox::warning(this, windowTitle(), tr("Make binding takes 10 FML, are you sure to continue?"), QMessageBox::Yes, QMessageBox::Cancel);
    if (ret != QMessageBox::Yes) {
        return;
    }

    auto from = CKeyID(plotID);
    auto target = boost::get<CKeyID>(toDest);
    auto action = MakeBindAction(from, target);
    CKey key;
    unsigned char hash[32];
    CSHA256().Write((const unsigned char*)fromMnem.data(), (size_t)fromMnem.length()).Finalize(hash);
    key.Set(hash, hash + 32, true);

    try {
        QString message;
        {
          TxFeeModifer feeUpdater(_walletModel->wallet());
          auto txid = _walletModel->wallet().sendAction(action, key, CTxDestination(from));
          message = tr("Transaction \"%1\" was created for plot id binding").arg(QString::fromStdString(txid.GetHex()));
        }

        QMessageBox::information(this, windowTitle(), message, QMessageBox::Ok, QMessageBox::Ok);
    } catch (const UniValue& ex) {
        std::map<std::string, UniValue> valMap;
        ex.getObjMap(valMap);
        auto code = valMap["code"].get_int();
        auto msg = valMap["message"].get_str();
        auto message = QString("got error code: %1, message: %2").arg(code).arg(QString::fromStdString(msg));
        QMessageBox::critical(this, windowTitle(), message, QMessageBox::Ok, QMessageBox::Ok);
    } catch (...) {
        QMessageBox::critical(this, windowTitle(), tr("Failed to create plot id binding transaction, please make sure there is enough balance in your wallet"), QMessageBox::Ok, QMessageBox::Ok);
    }
}

void PlotInfoPage::on_btnUnbind_clicked()
{
    if (!_walletModel || _walletModel->wallet().isLocked()) {
        QMessageBox::warning(this, windowTitle(), tr("Please unlock wallet to continue"), QMessageBox::Ok, QMessageBox::Ok);
        return;
    }

    auto fromMnem = ui->ebMnemonicFrom->text().trimmed().toStdString();
    auto fromAddr = ui->ebAddressFrom->text().trimmed();
    uint64_t plotID = poc::GeneratePlotId(fromMnem);

    if (std::to_string(plotID) != fromAddr.toStdString()) {
        QMessageBox::warning(this, windowTitle(), tr("passphrase and plotid mismatch"), QMessageBox::Ok, QMessageBox::Ok);
        return;
    }

    auto lock = _walletModel->requestUnlock();
    if (!lock.isValid()) {
      QMessageBox::warning(this, windowTitle(), tr("Failed to unlock wallet"), QMessageBox::Ok, QMessageBox::Ok);
      return;
    }

    auto fromPid = CKeyID(plotID);
    auto results = getBinding(fromPid);
    if (!results) {
      QMessageBox::information(this, windowTitle(), tr("No binding for this PlotID, please don't waste your money!"), QMessageBox::Ok, QMessageBox::Ok);
      return;
    }

    int ret = QMessageBox::warning(this, windowTitle(), tr("Unbinding takes 10 FML, are you sure to continue?"), QMessageBox::Yes, QMessageBox::Cancel);
    if (ret != QMessageBox::Yes) {
        return;
    }

    auto from = CKeyID(plotID);
    auto action = CAction(CUnbindAction(from));
    CKey key;
    unsigned char hash[32];
    CSHA256().Write((const unsigned char*)fromMnem.data(), (size_t)fromMnem.length()).Finalize(hash);
    key.Set(hash, hash + 32, true);

    try {
        QString message;
        {
          TxFeeModifer feeUpdater(_walletModel->wallet());
          auto txid = _walletModel->wallet().sendAction(action, key, CTxDestination(from));
          message = tr("Transaction \"%1\" was created for plot id unbinding").arg(QString::fromStdString(txid.GetHex()));
        }

        QMessageBox::information(this, windowTitle(), message, QMessageBox::Ok, QMessageBox::Ok);
    } catch (const UniValue& ex) {
        std::map<std::string, UniValue> valMap;
        ex.getObjMap(valMap);
        auto code = valMap["code"].get_int();
        auto msg = valMap["message"].get_str();
        auto message = QString("got error code: %1, message: %2").arg(code).arg(QString::fromStdString(msg));
        QMessageBox::critical(this, windowTitle(), message, QMessageBox::Ok, QMessageBox::Ok);
    } catch (...) {
        QMessageBox::critical(this, windowTitle(), tr("Failed to create unbind transaction, please make sure there is enough balance in your wallet"), QMessageBox::Ok, QMessageBox::Ok);
    }
}
