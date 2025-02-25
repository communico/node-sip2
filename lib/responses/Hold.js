'use strict';

const ResponseMessage = require('../ResponseMessage');

class HoldResponse extends ResponseMessage {

  parse(message) {
    
    this.identifier = '16';
    this.message = message;

    const data = {};

    data.ok = this.intToBool(this.message.charAt(2));
    data.available = this.charToBool(this.message.charAt(3));
    
    data.transactionDate = this.parseDateTime(this.message.substring(4, 22));
    data.expirationDate  = this.parseVariableWithoutDelimeter('BW', this.message.substring(22));
    data.queuePosition = this.parseVariable('BR', this.message.substring(22));
    data.pickupLocation = this.parseVariable('BS', this.message.substring(22));
    data.institutionId = this.parseVariable('AO', this.message.substring(22));
    data.patronIdentifier = this.parseVariable('AA', this.message.substring(22));
    data.itemIdentifier = this.parseVariable('AB', this.message.substring(22));
    data.titleIdentifier = this.parseVariable('AJ', this.message.substring(22));   
    data.screenMessage = this.parseVariableMulti('AF', this.message.substring(22));
    data.printLine = this.parseVariableMulti('AG', this.message.substring(22));
    if (this.parseSequence(this.message) !== '') {
      data.sequence = parseInt(this.parseSequence(this.message), 10);
    }
    data.checksum = this.parseChecksum(this.message);

    return data;
  }
}

module.exports = HoldResponse;
