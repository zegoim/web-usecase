!function(e,t){if("object"==typeof exports&&"object"==typeof module)module.exports=t();else if("function"==typeof define&&define.amd)define([],t);else{var r=t();for(var i in r)("object"==typeof exports?exports:e)[i]=r[i]}}("undefined"!=typeof self?self:this,(function(){return function(){"use strict";var e={5148:function(e,t){var r;Object.defineProperty(t,"__esModule",{value:!0}),t.ZEGO_WEBRTC_ACTION=void 0,(r=t.ZEGO_WEBRTC_ACTION||(t.ZEGO_WEBRTC_ACTION={})).PRELOAD_EFFECT="zc.pe.0",r.PLAY_EFFECT="zc.pe.1",r.PAUSE_EFFECT="zc.pe.2",r.RESUME_EFFECT="zc.re",r.STOP_EFFECT="zc.se",r.UNLOAD_EFFECT="zc.ue",r.SET_EFFECT_VOLUME="zc.sev",r.START_MIXING_AUDIO="zc.sma.0",r.STOP_MIXING_AUDIO="zc.sma.1",r.MIXING_BUFFER="zc.mb",r.STOP_MIXING_BUFFER="zc.smb",r.SET_MIXING_AUDIO_VOLUME="zc.smav",r.PUBLISHER_PLAY_EFFECT="zc.p.0.pe.0",r.PUBLISHER_PAUSE_EFFECT="zc.p.0.pe.1",r.PUBLISHER_RESUME_EFFECT="zc.p.0.re",r.PUBLISHER_STOP_EFFECT="zc.p.0.se",r.PUBLISHER_START_MIXING_AUDIO="zc.p.0.sma.0",r.PUBLISHER_STOP_MIXING_AUDIO="zc.p.0.sma.1",r.PUBLISHER_MIXING_BUFFER="zc.p.0.mb",r.PUBLISHER_SET_MIXING_AUDIO_VOLUME="zc.p.0.smav"},3782:function(e,t,r){Object.defineProperty(t,"__esModule",{value:!0}),t.AudioMix=void 0;var i=r(2519),o=function(){function e(e,t,r,i){this.logger=e,this.stateCenter=t,this.ac=r,this.mediaEleSources=i,this.audioBufferList=[],this.loop=!1,this.replace=!1,this.effectEndedCallBack=null,this.effectEndedListener=null,this.startTimes=0,this.startOffset=0,this.pauseTimes=0,this.resumeOffset=0,this.paused=!1,this.isMixAudio=!1,this.isMixingBuffer=!1,this.audioCurrentTimer=null}return e.prototype.preloadEffect=function(e,t){var r=this;this.logger.info("amu.pe.0 start preload effect");var i=new XMLHttpRequest;i.open("GET",e,!0),i.responseType="arraybuffer",i.onload=function(){if(200==i.status||304==i.status){var e=i.response;r.ac.resume(),r.ac.decodeAudioData(e,(function(e){r.logger.info("amu.pe.0 effect preload success"),t("",e)}),(function(e){t(e)}))}else{var o=i.statusText;t(o)}},i.send()},e.prototype.playEffect=function(e,t,r,i,o){var s=this;!0!==this.isMixAudio?this.audioBuffer?(this.startOffset=e||0,this.loop=t||!1,this.replace=r||!1,this.effectEndedCallBack=o,this.mixEffect(this.audioBuffer,(function(){s.buffSource.loop=!!t,e?s.buffSource.start(0,e/1e3):s.buffSource.start(0),s.startTimes=Date.now(),s.effectEndedListener=s.effectEndedHandler.bind(s),s.buffSource.addEventListener("ended",s.effectEndedListener),i&&i()}))):this.logger.error("amu.pe.1 no audio buffer found"):this.logger.error("amu.pe.1 audio is mixing")},e.prototype.mixingBuffer=function(e,t){var r=this;!0!==this.isMixAudio||0!=this.audioBufferList.length||0!=this.isMixingBuffer?(this.ac.resume(),this.ac.decodeAudioData(e,(function(e){r.audioBufferList.push(e),1==r.audioBufferList.length&&r.playRealTimeEffect(r.audioBufferList[0]),r.isMixingBuffer=!0,t&&t()}),(function(e){r.logger.error("amu.mb.0 "+e),t&&t({code:i.errorCodeList.PUBLISHER_DECODE_AUDIO_FAIL.code,message:i.errorCodeList.PUBLISHER_DECODE_AUDIO_FAIL.message+" "+e})}))):this.logger.error("amu.mb.0 audio is mixing")},e.prototype.stopMingBuffer=function(){return this.isMixingBuffer=!1,this.stopMixingAudio()},e.prototype.playRealTimeEffect=function(e){var t=this;this.mixEffect(e,(function(){t.buffSource&&t.buffSource.start(0),t.buffSource&&t.buffSource.addEventListener("ended",(function(){t.audioBufferList.shift(),t.audioBufferList.length>0&&t.isMixAudio&&t.playRealTimeEffect(t.audioBufferList[0])}))}))},e.prototype.pauseEffect=function(){this.audioBufferList.length>0?this.logger.error("amu.pe.0 real time buffer can not be paused"):(this.stopMixingAudio(),this.resumeOffset=(this.pauseTimes-this.startTimes+this.startOffset)%(1e3*this.audioBuffer.duration),this.paused=!0)},e.prototype.resumeEffect=function(){this.audioBufferList.length>0?this.logger.error("amu.pe.0 real time buffer can not be resume"):(this.playEffect(this.resumeOffset,this.loop,this.replace,void 0,this.effectEndedCallBack),this.startOffset=this.resumeOffset,this.paused=!1)},e.prototype.mixEffect=function(e,t){this.localStream?(this.ac.resume(),this.gainNode=this.ac.createGain(),this.buffSource=this.ac.createBufferSource(),this.buffSource.buffer=e,this.buffSource.connect(this.gainNode),this.gainNode.connect(this.ac.destination),this.replaceTrack()&&t()):this.logger.error("amu.me.0 localStream can not be found")},e.prototype.startMixingAudio=function(e,t){if(this.replace=t||!1,this.isMixAudio)return this.logger.error("amu.sma.0 audio is mixing"),!1;if(!this.localStream)return this.logger.error("amu.sma.0 localStream can not be found"),!1;if(e.captureStream=e.captureStream||e.mozCaptureStream||e.webkitCaptureStream,this.ac.resume(),this.gainNode=this.ac.createGain(),"safari"===this.stateCenter.browser){var r=this.mediaEleSources.find((function(t){return t.audio===e}));if(r)this.mixAudio=r.node;else{var i=this.ac.createMediaElementSource(e);this.mixAudio=i,this.mediaEleSources.push({audio:e,node:i})}e.currentTime=e.currentTime,this.audioCurrentTimer=setInterval((function(){e.currentTime=e.currentTime+.45}),6e3)}else this.mixAudio=this.ac.createMediaStreamSource(e.captureStream());return this.mixAudio.connect(this.gainNode),this.replaceTrack()},e.prototype.replaceTrack=function(){this.streamSource=this.ac.createMediaStreamSource(this.localStream),this.destination=this.ac.createMediaStreamDestination(),!this.replace&&this.streamSource.connect(this.destination),this.gainNode.connect(this.destination);var e=this.destination.stream.getAudioTracks()[0],t=this.peerConnection.getSenders().find((function(t){return t.track.kind===e.kind}));return t?(this.micTrack=this.localStream.getAudioTracks()[0],t.replaceTrack(e),this.localStream.removeTrack(this.micTrack),this.localStream.addTrack(e),this.isMixAudio=!0,!0):(this.logger.error("amu.rt.0 no sender"),!1)},e.prototype.stopMixingAudio=function(){var e=this;return this.paused?(this.logger.info("amu.sma.1 audioEffect paused"),!0):this.isMixAudio?this.localStream?(this.peerConnection.getSenders().find((function(t){return t.track.kind===e.micTrack.kind})),this.mixAudio?(this.mixAudio.disconnect(this.gainNode),this.mixAudio=null,this.audioCurrentTimer&&(clearInterval(this.audioCurrentTimer),this.audioCurrentTimer=null)):this.buffSource&&(this.buffSource.removeEventListener("ended",this.effectEndedListener),this.buffSource.stop(),this.pauseTimes=Date.now(),this.buffSource.disconnect(this.gainNode),this.buffSource=null),this.gainNode.disconnect(this.destination),this.isMixAudio=!1,this.audioBufferList=[],!0):(this.logger.error("amu.sma.1 localStream can not be found"),!1):(this.logger.warn("amu.sma.1 no mixing audio found"),!0)},e.prototype.setMixingAudioVolume=function(e){return this.gainNode?(this.gainNode.gain.value=e,!0):(this.logger.error("amu.sma.2 no mixing audio found"),!1)},e.prototype.effectEndedHandler=function(){this.stopMixingAudio(),this.effectEndedCallBack&&this.effectEndedCallBack()},e}();t.AudioMix=o},9179:function(e,t,r){Object.defineProperty(t,"__esModule",{value:!0}),t.AudioMixModule=void 0;var i=r(5148),o=r(7214),s=function(){function e(e,t,r,i,o){this.logger=e,this.dataReport=t,this.stateCenter=r,this.streamCenter=i,this.ac=o,this.buffer=null,this.blank=null,"safari"==this.stateCenter.browser&&null==this.blank&&null==this.buffer&&(this.ac.resume(),this.buffer=this.ac.createBuffer(1,1,this.ac.sampleRate),this.blank=this.ac.createBufferSource(),this.blank.buffer=this.buffer,this.blank.connect(this.ac.destination),this.blank.start())}return e.prototype.preloadEffect=function(e,t,r){e&&"string"==typeof e&&t&&"string"==typeof t?this.stateCenter.audioEffectBuffer[e]?this.logger.error(i.ZEGO_WEBRTC_ACTION.PRELOAD_EFFECT+" audio buffer already exists"):(this.logger.info(i.ZEGO_WEBRTC_ACTION.PRELOAD_EFFECT+" start preload effect"),this._preloadEffect(this.ac,e,t,r)):this.logger.error(i.ZEGO_WEBRTC_ACTION.PRELOAD_EFFECT+" params error")},e.prototype.playEffect=function(e,t,r){e.streamID&&"string"==typeof e.streamID&&e.effectID&&"string"==typeof e.effectID?this.stateCenter.audioEffectBuffer[e.effectID]?this._playEffect(e,t,r):this.logger.error(i.ZEGO_WEBRTC_ACTION.PLAY_EFFECT+" audio buffer doesn't exists"):this.logger.error(i.ZEGO_WEBRTC_ACTION.PLAY_EFFECT+" params error")},e.prototype.pauseEffect=function(e,t){return e&&"string"==typeof e?(t&&"string"!=typeof t&&this.logger.error(i.ZEGO_WEBRTC_ACTION.PAUSE_EFFECT+" effect "),this._pauseEffect(e,t)):(this.logger.error(i.ZEGO_WEBRTC_ACTION.PAUSE_EFFECT+" streamID format error"),!1)},e.prototype.resumeEffect=function(e,t){return e&&"string"==typeof e?(t&&"string"!=typeof t&&this.logger.error(i.ZEGO_WEBRTC_ACTION.RESUME_EFFECT+" effect "),this._resumeEffect(e,t)):(this.logger.error(i.ZEGO_WEBRTC_ACTION.RESUME_EFFECT+" streamID format error"),!1)},e.prototype.stopEffect=function(e,t){return e&&"string"==typeof e?(t&&"string"!=typeof t&&this.logger.error(i.ZEGO_WEBRTC_ACTION.STOP_EFFECT+" effect "),this._stopEffect(e,t)):(this.logger.error(i.ZEGO_WEBRTC_ACTION.STOP_EFFECT+" streamID format error"),!1)},e.prototype.unloadEffect=function(e){return e&&"string"==typeof e?(delete this.stateCenter.audioEffectBuffer[e],!0):(this.logger.error(i.ZEGO_WEBRTC_ACTION.UNLOAD_EFFECT+" params error"),!1)},e.prototype.setEffectVolume=function(e,t,r){if(!e||"string"!=typeof e)return this.logger.error(i.ZEGO_WEBRTC_ACTION.SET_EFFECT_VOLUME+" streamID format error"),!1;r&&"string"!=typeof r&&this.logger.error(i.ZEGO_WEBRTC_ACTION.SET_EFFECT_VOLUME+" effect ");var o=this.streamCenter.getPublisher(e);return o?o.setEffectVolume(t/100,r):(this.logger.error(i.ZEGO_WEBRTC_ACTION.SET_EFFECT_VOLUME+" publisher doesn't exist"),!1)},e.prototype.startMixingAudio=function(e,t){return this.logger.info(i.ZEGO_WEBRTC_ACTION.START_MIXING_AUDIO+" call "+e),e&&"string"==typeof e?t?(this.logger.info(i.ZEGO_WEBRTC_ACTION.START_MIXING_AUDIO+" end "+e),Array.isArray(t)&&0!==t.length?this._startMixingAudio(e,t):(this.logger.error(i.ZEGO_WEBRTC_ACTION.START_MIXING_AUDIO+" audio param type error"),!1)):(this.logger.error(i.ZEGO_WEBRTC_ACTION.START_MIXING_AUDIO+" no audio"),!1):(this.logger.error(i.ZEGO_WEBRTC_ACTION.START_MIXING_AUDIO+" stream id type error"),!1)},e.prototype.stopMixingAudio=function(e,t){return e&&"string"==typeof e?Array.isArray(t)&&0!==t.length||void 0===t?this._stopMixingAudio(e,t):(this.logger.error(i.ZEGO_WEBRTC_ACTION.STOP_MIXING_AUDIO+" audio param type error"),!1):(this.logger.error(i.ZEGO_WEBRTC_ACTION.STOP_MIXING_AUDIO+" param streamID format error"),!1)},e.prototype.mixingBuffer=function(e,t,r,o){this.logger.info(i.ZEGO_WEBRTC_ACTION.MIXING_BUFFER+" call streamID: "+e+" sourceID:"+t),e&&"string"==typeof e?t&&"string"==typeof t?(this._mixingBuffer(e,t,r,o),this.logger.info(i.ZEGO_WEBRTC_ACTION.MIXING_BUFFER+" end")):this.logger.error(i.ZEGO_WEBRTC_ACTION.MIXING_BUFFER+" param source id format error"):this.logger.error(i.ZEGO_WEBRTC_ACTION.MIXING_BUFFER+" param streamid format error")},e.prototype.stopMixingBuffer=function(e,t){return this.logger.info(i.ZEGO_WEBRTC_ACTION.STOP_MIXING_BUFFER+" call streamID: "+e+" sourceID:"+t),e&&"string"==typeof e?t&&"string"==typeof t?this._stopMixingBuffer(e,t):(this.logger.error(i.ZEGO_WEBRTC_ACTION.STOP_MIXING_BUFFER+" param source id format error"),!1):(this.logger.error(i.ZEGO_WEBRTC_ACTION.STOP_MIXING_BUFFER+" param streamid format error"),!1)},e.prototype.setMixingAudioVolume=function(e,t,r){return this.logger.info(i.ZEGO_WEBRTC_ACTION.SET_MIXING_AUDIO_VOLUME+" call"),"string"!=typeof e||""==e?(this.logger.error(i.ZEGO_WEBRTC_ACTION.SET_MIXING_AUDIO_VOLUME+" stream ID must be string and not empty"),!1):"number"!=typeof t||t<0||t>100?(this.logger.error(i.ZEGO_WEBRTC_ACTION.SET_MIXING_AUDIO_VOLUME+" volume must be a number between 0 and 100"),!1):r&&r instanceof HTMLMediaElement?this._setMixingAudioVolume(e,t,r):(this.logger.error(i.ZEGO_WEBRTC_ACTION.SET_MIXING_AUDIO_VOLUME+" no audio"),!1)},e.prototype.getSoundLevel=function(e,t,r){this.logger.info("zc.gsl call");var i=this.stateCenter.getReportSeq();this.dataReport.newReport(i,o.ZegoRTCLogEvent.kZegoTaskGetSoundLevel.event);try{this.ac.resume();var s=this.ac.createMediaStreamSource(e),n=this.ac.createScriptProcessor(4096,1,1);this.stateCenter.audioStreamList[e.id]={mic:s,script:n},s.connect(n),n.connect(this.ac.destination),n.onaudioprocess=function(e){for(var r=e.inputBuffer.getChannelData(0),i=0,o=0;o<r.length;o++)i<r[o]&&(i=r[o]);t(i)},this.dataReport.uploadReport(i)}catch(e){r(e),this.dataReport.addMsgInfo(i,o.ZegoRTCLogEvent.kZegoTaskGetSoundLevel.error.kGetSoundLevelError),this.dataReport.uploadReport(i)}this.logger.info("zc.gsl call success")},e.prototype.stopSoundLevel=function(e){this.logger.info("zc.ssl call");var t=this.stateCenter.getReportSeq();this.dataReport.newReport(t,o.ZegoRTCLogEvent.kZegoTaskStopSoundLevel);var r=this.stateCenter.audioStreamList[e.id];r.mic.disconnect(),r.script.disconnect(),delete this.stateCenter.audioStreamList[e.id],this.dataReport.uploadReport(t)},e.prototype._preloadEffect=function(e,t,r,i){var o=this,s=new XMLHttpRequest;s.open("GET",r,!0),s.responseType="arraybuffer",s.onload=function(){if(200==s.status||304==s.status){var r=s.response;e.decodeAudioData(r,(function(e){o.logger.info("zc.pe.0 effect preload success"),o.stateCenter.audioEffectBuffer[t]=e,i&&i()}),(function(e){o.logger.error("zc.pe.0 effect preload fail "+e),i&&i(e)}))}else{var n=s.statusText;o.logger.error("zc.pe.0 effect preload fail "+n),i&&i(n)}},s.send()},e.prototype._playEffect=function(e,t,r){var i=this.stateCenter.audioEffectBuffer[e.effectID],o=this.streamCenter.getPublisher(e.streamID);o?i?o.playEffect(e,i,t,r):this.logger.error("zc.pe.1 no audio buffer found"):this.logger.error("zc.pe.1 publisher doesn't exist")},e.prototype._pauseEffect=function(e,t){var r=this.streamCenter.getPublisher(e);return r?r.pauseEffect(t):(this.logger.error("zc.pe.2 publisher doesn't exist"),!1)},e.prototype._resumeEffect=function(e,t){var r=this.streamCenter.getPublisher(e);return r?r.resumeEffect(t):(this.logger.error("zc.re.0 publisher doesn't exist"),!1)},e.prototype._stopEffect=function(e,t){var r=this.streamCenter.getPublisher(e);return r?r.stopEffect(t):(this.logger.error("zc.re.0 publisher doesn't exist"),!1)},e.prototype._setMixingAudioVolume=function(e,t,r){var i=this.streamCenter.getPublisher(e);return i?i.setMixingAudioVolume(t/100,r):(this.logger.error("zc.sma.2 publisher doesn't exist"),!1)},e.prototype._startMixingAudio=function(e,t){var r=this.streamCenter.getPublisher(e);return r?r.startMixingAudio(t):(this.logger.error("zc.sma.0 publisher doesn't exist"),!1)},e.prototype._stopMixingAudio=function(e,t){var r=this.streamCenter.getPublisher(e);return r?r.stopMixingAudio(t):(this.logger.error("zc.sma.1 publisher doesn't exist"),!1)},e.prototype._mixingBuffer=function(e,t,r,i){var o=this.streamCenter.getPublisher(e);o?r instanceof ArrayBuffer?o.mixingBuffer(t,r,i):this.logger.error("zc.mb.0 array buffer not found"):this.logger.error("zc.mb.0 publisher doesn't exist")},e.prototype._stopMixingBuffer=function(e,t){var r=this.streamCenter.getPublisher(e);return r?r.stopMixingBuffer(t):(this.logger.error("zc.sma.1 publisher doesn't exist"),!1)},e}();t.AudioMixModule=s},5096:function(e,t,r){Object.defineProperty(t,"__esModule",{value:!0}),t.publisher=void 0;var i=r(5148),o=r(3782);t.publisher={playEffect:function(e,t,r,s){if(this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_PLAY_EFFECT+""+this.streamId+" call"),this.effectList.find((function(r){return r.effectID==e.effectID&&r.audioBuffer==t})))this.logger.warn(i.ZEGO_WEBRTC_ACTION.PUBLISHER_PLAY_EFFECT+""+this.streamId+" effect alreadly exist ");else{this.streamCenter.soundLevelDelegate&&this.stopSoundLevel();var n=new o.AudioMix(this.logger,this.stateCenter,this.ac,this.mediaEleSources);n.localStream=this.localStream,n.peerConnection=this.peerConnection,n.audioBuffer=t,this.effectList.push({audioMix:n,effectID:e.effectID,audioBuffer:t}),n.playEffect(e.playTime,e.loop,!1,r,s),this.streamCenter.soundLevelDelegate&&this.startSoundLevel(),this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_PLAY_EFFECT+""+this.streamId+" play effect "+e.effectID+" success")}},pauseEffect:function(e){var t=this.effectList.find((function(t){return t.effectID==e}));if(t)this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),t.audioMix.pauseEffect(),this.streamCenter.soundLevelDelegate&&this.startSoundLevel(),this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_PAUSE_EFFECT+" "+this.streamId+" pause "+e+" success");else{if(void 0!==e)return this.logger.error(i.ZEGO_WEBRTC_ACTION.PUBLISHER_PAUSE_EFFECT+" "+this.streamId+" no effect ID found"),!1;this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),this.effectList.forEach((function(e){return e.audioMix.pauseEffect()})),this.streamCenter.soundLevelDelegate&&this.startSoundLevel()}return!0},resumeEffect:function(e){var t=this.effectList.find((function(t){return t.effectID==e}));if(t)this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),t.audioMix.resumeEffect(),this.streamCenter.soundLevelDelegate&&this.startSoundLevel(),this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_RESUME_EFFECT+" "+this.streamId+" resume"+e+" success");else{if(void 0!==e)return this.logger.error(i.ZEGO_WEBRTC_ACTION.PUBLISHER_RESUME_EFFECT+" "+this.streamId+" no effect ID found"),!1;this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),this.effectList.forEach((function(e){return e.audioMix.resumeEffect()})),this.streamCenter.soundLevelDelegate&&this.startSoundLevel()}return!1},stopEffect:function(e){var t=this.effectList.find((function(t){return t.effectID==e}));if(t)this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),t.audioMix.stopMixingAudio(),this.effectList.splice(this.effectList.indexOf(t),1),this.streamCenter.soundLevelDelegate&&this.startSoundLevel(),this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_STOP_EFFECT+" "+this.streamId+" pause "+e+" success");else{if(void 0!==e)return this.logger.error(i.ZEGO_WEBRTC_ACTION.PUBLISHER_STOP_EFFECT+" "+this.streamId+" no effect ID found"),!1;this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),this.effectList.forEach((function(e){return e.audioMix.stopMixingAudio()})),this.effectList=[],this.streamCenter.soundLevelDelegate&&this.startSoundLevel()}return!0},setEffectVolume:function(e,t){var r=this.effectList.find((function(e){return e.effectID==t}));if(r)r.audioMix.setMixingAudioVolume(e),this.logger.info("zp.sev.0 "+this.streamId+" set volume "+t+" success");else{if(void 0!==t)return this.logger.error("zp.sev.0 "+this.streamId+" no effect ID found"),!1;this.effectList.forEach((function(t){return t.audioMix.setMixingAudioVolume(e)}))}return!0},startMixingAudio:function(e){var t=this;return this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_START_MIXING_AUDIO+" "+this.streamId+" call"),this.localStream?(this.micTrack||(this.micTrack=this.localStream.getAudioTracks().length>0?this.localStream.getAudioTracks()[0]:null),e.forEach((function(e){if(t.audioMixList.find((function(t){return t.media==e})))t.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_START_MIXING_AUDIO+" "+t.streamId+" mix audio already exist");else{t.streamCenter.soundLevelDelegate&&t.stopSoundLevel();var r=new o.AudioMix(t.logger,t.stateCenter,t.ac,t.mediaEleSources);r.localStream=t.localStream,r.peerConnection=t.peerConnection,t.audioMixList.push({audioMix:r,media:e}),r.startMixingAudio(e),t.streamCenter.soundLevelDelegate&&t.startSoundLevel()}})),!0):(this.logger.error(i.ZEGO_WEBRTC_ACTION.PUBLISHER_START_MIXING_AUDIO+" localStream not found"),!1)},stopMixingAudio:function(e){var t=this;return this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_STOP_MIXING_AUDIO+" "+this.streamId+" call"),e?e.forEach((function(e){for(var r=0;r<t.audioMixList.length;r++)if(t.audioMixList[r].media==e){t.audioMixList[r].audioMix.stopMixingAudio()&&t.audioMixList.splice(r--,1);break}})):(this.audioMixList.forEach((function(e){return e.audioMix.stopMixingAudio()})),this.audioMixList=[]),!0},mixingBuffer:function(e,t,r){var s=this;if(this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_MIXING_BUFFER+" "+this.streamId+" call"),this.micTrack||(this.micTrack=this.localStream.getAudioTracks().length>0?this.localStream.getAudioTracks()[0]:null),this.arrayBufferMap[e])this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),this.arrayBufferMap[e].mixingBuffer(t,(function(){s.streamCenter.soundLevelDelegate&&s.startSoundLevel(),r&&r()}));else{this.streamCenter.soundLevelDelegate&&this.stopSoundLevel();var n=new o.AudioMix(this.logger,this.stateCenter,this.ac,this.mediaEleSources);n.localStream=this.localStream,n.peerConnection=this.peerConnection,this.arrayBufferMap[e]=n,n.mixingBuffer(t,(function(){s.streamCenter.soundLevelDelegate&&s.startSoundLevel(),r&&r()}))}},stopMixingBuffer:function(e){if(e&&this.arrayBufferMap[e])return this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),this.arrayBufferMap[e].stopMingBuffer(),delete this.arrayBufferMap[e],this.streamCenter.soundLevelDelegate&&this.startSoundLevel(),!0;if(void 0===e){for(var t in this.streamCenter.soundLevelDelegate&&this.stopSoundLevel(),this.arrayBufferMap)this.arrayBufferMap[t].stopMingBuffer();return this.streamCenter.soundLevelDelegate&&this.startSoundLevel(),!0}return this.logger.warn(i.ZEGO_WEBRTC_ACTION.PUBLISHER_MIXING_BUFFER+" "+this.streamId+" arrayBuffer no found"),!1},setMixingAudioVolume:function(e,t){this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_SET_MIXING_AUDIO_VOLUME+" "+this.streamId+" call");var r=this.audioMixList.find((function(e){return e.media===t}));return r?(r.audioMix.setMixingAudioVolume(e),this.logger.info(i.ZEGO_WEBRTC_ACTION.PUBLISHER_SET_MIXING_AUDIO_VOLUME+" "+this.streamId+" call success"),!0):(this.logger.error(i.ZEGO_WEBRTC_ACTION.PUBLISHER_SET_MIXING_AUDIO_VOLUME+" "+this.streamId+" audio is not mixing"),!1)}}},2519:function(e,t){Object.defineProperty(t,"__esModule",{value:!0}),t.errorCodeList=void 0,t.errorCodeList={GET_SOUND_LEVEL_FAIL:{code:1000019,message:"get sound level error"},PUBLISHER_DECODE_AUDIO_FAIL:{code:1103057,message:"decode audio data fail"}}},7214:function(e,t,r){Object.defineProperty(t,"__esModule",{value:!0}),t.ZegoRTCLogEvent=void 0;var i=r(2519);t.ZegoRTCLogEvent={kZegoTaskGetSoundLevel:{event:"/sdk/get_sound_level",error:{kGetSoundLevelError:i.errorCodeList.GET_SOUND_LEVEL_FAIL}},kZegoTaskStopSoundLevel:"/sdk/stop_sound_level"}}},t={};function r(i){var o=t[i];if(void 0!==o)return o.exports;var s=t[i]={exports:{}};return e[i](s,s.exports,r),s.exports}var i={};return function(){var e=i;Object.defineProperty(e,"__esModule",{value:!0});var t=r(9179),o=r(5096);e.default={type:"AudioMix",install:function(e,r){for(var i in Object.defineProperty(e.prototype,"initAudioMix",{value:function(){this.audioMixModule=new t.AudioMixModule(this.logger,this.dataReport,this.stateCenter,this.streamCenter,this.ac)}}),o.publisher)Object.defineProperty(r.prototype,i,{value:o.publisher[i],writable:!1})}}}(),i}()}));