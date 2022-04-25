!function(e,t){if("object"==typeof exports&&"object"==typeof module)module.exports=t();else if("function"==typeof define&&define.amd)define([],t);else{var n=t();for(var a in n)("object"==typeof exports?exports:e)[a]=n[a]}}("undefined"!=typeof self?self:this,(function(){return function(){"use strict";var e={8835:function(e,t,n){Object.defineProperty(t,"__esModule",{value:!0}),t.ZegoRealTimeSequentialDataManager=void 0;var a=n(3504),r=function(){function e(e,t){this.dataChannelManager=new a.DataChannelListener(e,t)}return e.prototype.startBroadcasting=function(e){return this.dataChannelManager.startBroadcasting(e)},e.prototype.stopBroadcasting=function(e){return this.dataChannelManager.stopBroadcasting(e)},e.prototype.sendRealTimeSequentialData=function(e,t){return this.dataChannelManager.sendRealTimeSequentialData(e,t)},e.prototype.startSubscribing=function(e){return this.dataChannelManager.startSubscribing(e)},e.prototype.stopSubscribing=function(e){return this.dataChannelManager.stopSubscribing(e)},e.prototype.on=function(e,t){this.dataChannelManager.on(e,t)},e.prototype.off=function(e,t){this.dataChannelManager.off(e,t)},e}();t.ZegoRealTimeSequentialDataManager=r},3504:function(e,t){var n=this&&this.__awaiter||function(e,t,n,a){return new(n||(n=Promise))((function(r,i){function o(e){try{l(a.next(e))}catch(e){i(e)}}function s(e){try{l(a.throw(e))}catch(e){i(e)}}function l(e){var t;e.done?r(e.value):(t=e.value,t instanceof n?t:new n((function(e){e(t)}))).then(o,s)}l((a=a.apply(e,t||[])).next())}))},a=this&&this.__generator||function(e,t){var n,a,r,i,o={label:0,sent:function(){if(1&r[0])throw r[1];return r[1]},trys:[],ops:[]};return i={next:s(0),throw:s(1),return:s(2)},"function"==typeof Symbol&&(i[Symbol.iterator]=function(){return this}),i;function s(i){return function(s){return function(i){if(n)throw new TypeError("Generator is already executing.");for(;o;)try{if(n=1,a&&(r=2&i[0]?a.return:i[0]?a.throw||((r=a.return)&&r.call(a),0):a.next)&&!(r=r.call(a,i[1])).done)return r;switch(a=0,r&&(i=[2&i[0],r.value]),i[0]){case 0:case 1:r=i;break;case 4:return o.label++,{value:i[1],done:!1};case 5:o.label++,a=i[1],i=[0];continue;case 7:i=o.ops.pop(),o.trys.pop();continue;default:if(!((r=(r=o.trys).length>0&&r[r.length-1])||6!==i[0]&&2!==i[0])){o=0;continue}if(3===i[0]&&(!r||i[1]>r[0]&&i[1]<r[3])){o.label=i[1];break}if(6===i[0]&&o.label<r[1]){o.label=r[1],r=i;break}if(r&&o.label<r[2]){o.label=r[2],o.ops.push(i);break}r[2]&&o.ops.pop(),o.trys.pop();continue}i=t.call(e,o)}catch(e){i=[6,e],a=0}finally{n=r=0}if(5&i[0])throw i[1];return{value:i[0]?i[1]:void 0,done:!0}}([i,s])}}};Object.defineProperty(t,"__esModule",{value:!0}),t.DataChannelListener=void 0;var r=function(){function e(e,t){this.zegoWebRTC=e,this.roomID=t,this.pubDataChannelList=[],this.subDataChannelList=[],this.listenerList={receiveRealTimeSequentialData:[]},this.logger=e.logger}return e.prototype.startBroadcasting=function(e,t){return n(this,void 0,void 0,(function(){var t,n,r,i;return a(this,(function(a){switch(a.label){case 0:return this.logger.info("dc.sb.0 call"),this.pubDataChannelList.includes(e)?(this.logger.error("dc.sb.0 datachannel already exist"),[2,!1]):(t=this.zegoWebRTC.streamCenter.publisherList[e])&&t.publisher.dataChannel?(this.pubDataChannelList.push(e),[2,!0]):t&&!t.publisher.dataChannel?(this.logger.error("dc.sb.0 publish datachannel no exist, try other stream ID"),[2,!1]):this.broadcastStream?[3,2]:(n=document.createElement("canvas"),r=this,[4,this.zegoWebRTC.createStream({custom:{source:n}})]);case 1:r.broadcastStream=a.sent(),a.label=2;case 2:return(i=this.zegoWebRTC.startPublishingStream(e,this.broadcastStream,{roomID:this.roomID},!0))&&this.pubDataChannelList.push(e),this.logger.info("dc.sb.0 end"),[2,i]}}))}))},e.prototype.stopBroadcasting=function(e){this.logger.info("dc.sb.1 call"),this.pubDataChannelList=this.pubDataChannelList.filter((function(t){return t!==e}));var t=this.zegoWebRTC.streamCenter.publisherList[e];return t?(t.room.roomID==this.roomID&&t.isDataChannel&&this.zegoWebRTC.stopPublishingStream(e),this.logger.info("dc.sb.1 end"),!0):(this.logger.error("dc.sb.1 datachannel no found"),!1)},e.prototype.sendRealTimeSequentialData=function(e,t){if(!t instanceof ArrayBuffer)return this.logger.error("dc.srsd data type wrong"),!1;var n=this.zegoWebRTC.streamCenter.publisherList[e];return n&&this.pubDataChannelList.includes(e)?this.sendBCMessage(n.publisher,t):(this.logger.error("dc.srsd datachannel no found"),!1)},e.prototype.sendBCMessage=function(e,t){var n;if(!e.dataChannelState)return!1;for(var a=new Uint8Array(t),r=0,i=t.byteLength,o=e.send_seq,s=0,l=(new Date).getTime(),h=0;i>0;){i>1151?h=1141:(h=i,s=1);var u=new Uint8Array(h+10);u[0]=1,u[1]=s,u[2]=e.send_seq>>8&255,u[3]=255&e.send_seq,u[4]=o>>8&255,u[5]=255&o,u[6]=l>>24&255,u[7]=l>>16&255,u[8]=l>>8&255,u[9]=255&l;for(var c=0;c<h;c++)u[c+10]=a[c+r];i-=h,r+=h,e.send_seq++,e.send_seq>=65536&&(e.send_seq=0),null===(n=e.dataChannel)||void 0===n||n.send(u)}return!0},e.prototype.startSubscribing=function(e,t){var r,i;return n(this,void 0,void 0,(function(){var t,n;return a(this,(function(a){switch(a.label){case 0:return this.logger.info("dc.ss.0 call"),this.subDataChannelList.includes(e)?(this.logger.error("dc.ss.0 datachannel already exist"),[2,!1]):(t=this.zegoWebRTC.streamCenter.playerList[e])?[3,2]:[4,this.zegoWebRTC.startPlayingStream(e,void 0,!0)];case 1:a.sent(),t=this.zegoWebRTC.streamCenter.playerList[e],a.label=2;case 2:return(n=t.player).dataChannel?(!(null===(r=n.onDataChannelList)||void 0===r?void 0:r.includes(this.onReceivedDataChannel.bind(this)))&&(null===(i=n.onDataChannelList)||void 0===i||i.push(this.onReceivedDataChannel.bind(this))),this.subDataChannelList.push(e),this.logger.info("dc.ss.0 end"),[2,!0]):(this.logger.error("dc.ss.0 datachannel no exist, try other stream ID"),[2,!1])}}))}))},e.prototype.stopSubscribing=function(e){this.logger.info("dc.ss.1 call"),this.subDataChannelList=this.subDataChannelList.filter((function(t){return t!==e}));var t=this.zegoWebRTC.streamCenter.playerList[e];return t?(t.room.roomID==this.roomID&&t.isDataChannel&&this.zegoWebRTC.stopPlayingStream(e),this.logger.info("dc.ss.1 end"),!0):(this.logger.error("dc.ss.1 datachannel no subscribe"),!1)},e.prototype.on=function(e,t){this.bindListener(e,t)},e.prototype.off=function(e,t){this.deleteListener(e,t)},e.prototype.bindListener=function(e,t){return this.listenerList[e]?"function"!=typeof t?(this.logger.error("zc.o.0 listener callBack must be funciton"),!1):(-1==this.listenerList[e].indexOf(t)&&this.listenerList[e].push(t),!0):(this.logger.error("dc.o.0 event "+e+" no found"),!1)},e.prototype.deleteListener=function(e,t){if(!this.listenerList[e])return this.logger.error("dc.o.1 listener no found"),!1;var n=this.listenerList[e];return t?n.splice(n.indexOf(t),1):this.listenerList[e]=[],!0},e.prototype.actionListener=function(e){for(var t=this,n=[],a=1;a<arguments.length;a++)n[a-1]=arguments[a];this.listenerList[e]&&this.listenerList[e].forEach((function(a){try{setTimeout((function(){a.apply(void 0,n)}),0)}catch(n){t.logger.error("dc.al "+e+" "+n)}}))},e.prototype.onReceivedDataChannel=function(e,t,n){this.actionListener("receiveRealTimeSequentialData",e,t,n)},e.prototype.reset=function(){var e=this;for(var t in this.logger.info("dc.rs call"),this.pubDataChannelList.forEach((function(t){var n=e.zegoWebRTC.streamCenter.publisherList[t];n&&n.room.roomID==e.roomID&&n.isDataChannel&&e.zegoWebRTC.stopPublishingStream(t)})),this.subDataChannelList.forEach((function(t){var n=e.zegoWebRTC.streamCenter.playerList[t];n&&n.room.roomID==e.roomID&&n.isDataChannel&&e.zegoWebRTC.stopPlayingStream(t)})),this.listenerList)this.listenerList[t]=[];this.broadcastStream&&this.zegoWebRTC.destroyStream(this.broadcastStream),this.broadcastStream=void 0,this.logger.info("dc.rs end")},e}();t.DataChannelListener=r}},t={};function n(a){var r=t[a];if(void 0!==r)return r.exports;var i=t[a]={exports:{}};return e[a].call(i.exports,i,i.exports,n),i.exports}var a={};return function(){var e=a;Object.defineProperty(e,"__esModule",{value:!0}),e.DataChannel=void 0;var t=n(8835);e.DataChannel={type:"DataChannel",install:function(e){Object.defineProperty(e.prototype,"createRealTimeSequentialDataManager",{value:function(e){this.enableDataChannel(!0);var n=this.stateCenter.getRoomByRoomID(e);return n?n.dataChannelManager?null:(n.dataChannelManager=new t.ZegoRealTimeSequentialDataManager(this,e),n.dataChannelManager):(this.logger.error("zc.crsdm room no exist"),null)},writable:!1}),Object.defineProperty(e.prototype,"destroyRealTimeSequentialDataManager",{value:function(e){var t=this.stateCenter.roomList.find((function(t){return t.dataChannelManager==e}));t&&(e.dataChannelManager.reset(),t.dataChannelManager=null)},writable:!1})}}}(),a}()}));