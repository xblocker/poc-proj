// Copyright (c) 2011-2019 The Fermat Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FERMAT_QT_MINERVIEWPAGE_H
#define FERMAT_QT_MINERVIEWPAGE_H

#include <QWidget>

class PlatformStyle;
namespace Ui {
    class MinerviewPage;
}

/** Overview ("miner") page widget */
class MinerviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit MinerviewPage(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~MinerviewPage();

private:
    Ui::MinerviewPage *ui;
};

#endif // FERMAT_QT_MINERVIEWPAGE_H
