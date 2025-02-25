'use strict';

const RequestMessage = require('../RequestMessage');

class HoldRequest extends RequestMessage {
  // 15<hold mode><transaction date><expiration date><pickup location><hold type><institution id><patron identifier><patron password><item identifier><title identifier><terminal password><fee acknowledged> 

  // mode 1-char, fixed-length required field  '+'/'-'/'*'  Add, delete, change 
  // hold type     BY     1-char, fixed-length field (1 thru 9).  The type of hold:
  //    Value   HoldType
  //      1     other     
  //      2     any copy of a title     
  //      3     a specific copy of a title     
  //      4     any copy at a single branch or sublocation
  // expiration date      BW    18-char, fixed-length field:  YYYYMMDDZZZZHHMMSS; the date, if any, that the hold will expire.
  // pickup location     BS      variable-length field; the location where an item will be picked up. 
  constructor(mode, holdType, itemIdentifier, titleIdentifier = '', pickupLocation ='',feeAcknowledged, expirationDate = '                  ') {
    super('15');

    this.mode = mode; // either '+'/'-'/'*'  Add, delete, change
    this.holdType = holdType;
    this.itemIdentifier = itemIdentifier;
    this.titleIdentifier = titleIdentifier;
    this.pickupLocation = pickupLocation;
    this.transactionDate = RequestMessage.getDateTime();
    this.expirationDate = expirationDate;
    this.feeAcknowledged = feeAcknowledged || null;
  }

  buildMessage() {
    this.append(this.mode);
    this.append(this.transactionDate);
    this.append('BW');
    this.append(this.expirationDate);
    this.append('|BS');
    this.append(this.pickupLocation);
    this.append('|BY');
    this.append(this.holdType);
    this.append('|AO');
    this.append(this.institutionId);
    this.append('|AA');
    this.append(this.patronIdentifier);
    this.append('|AD');
    this.append(this.patronPassword);
    this.append('|AB');
    this.append(this.itemIdentifier);
    this.append('|AJ');
    this.append(this.titleIdentifier);
    this.append('|AC');
    this.append(this.terminalPassword);
    if (this.feeAcknowledged !== null) {
      this.append('|BO');
      this.append(this.feeAcknowledged ? 'Y' : 'N');
    }
    
  }
}

module.exports = HoldRequest;
