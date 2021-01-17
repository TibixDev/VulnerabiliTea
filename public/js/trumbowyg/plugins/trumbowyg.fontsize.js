!function(e){"use strict";e.extend(!0,e.trumbowyg,{langs:{en:{fontsize:"Font size",fontsizes:{"x-small":"Extra small",small:"Small",medium:"Regular",large:"Large","x-large":"Extra large",custom:"Custom"},fontCustomSize:{title:"Custom Font Size",label:"Font Size",value:"48px"}},da:{fontsize:"Skriftstørrelse",fontsizes:{"x-small":"Ekstra lille",small:"Lille",medium:"Normal",large:"Stor","x-large":"Ekstra stor",custom:"Brugerdefineret"}},de:{fontsize:"Schriftgröße",fontsizes:{"x-small":"Sehr klein",small:"Klein",medium:"Normal",large:"Groß","x-large":"Sehr groß",custom:"Benutzerdefiniert"},fontCustomSize:{title:"Benutzerdefinierte Schriftgröße",label:"Schriftgröße",value:"48px"}},es:{fontsize:"Tamaño de Fuente",fontsizes:{"x-small":"Extra pequeña",small:"Pegueña",medium:"Regular",large:"Grande","x-large":"Extra Grande",custom:"Customizada"},fontCustomSize:{title:"Tamaño de Fuente Customizada",label:"Tamaño de Fuente",value:"48px"}},fr:{fontsize:"Taille de la police",fontsizes:{"x-small":"Très petit",small:"Petit",medium:"Normal",large:"Grand","x-large":"Très grand",custom:"Taille personnalisée"},fontCustomSize:{title:"Taille de police personnalisée",label:"Taille de la police",value:"48px"}},hu:{fontsize:"Betű méret",fontsizes:{"x-small":"Extra kicsi",small:"Kicsi",medium:"Normális",large:"Nagy","x-large":"Extra nagy",custom:"Egyedi"},fontCustomSize:{title:"Egyedi betű méret",label:"Betű méret",value:"48px"}},it:{fontsize:"Dimensioni del testo",fontsizes:{"x-small":"Molto piccolo",small:"piccolo",regular:"normale",large:"grande","x-large":"Molto grande",custom:"Personalizzato"},fontCustomSize:{title:"Dimensioni del testo personalizzato",label:"Dimensioni del testo",value:"48px"}},ko:{fontsize:"글꼴 크기",fontsizes:{"x-small":"아주 작게",small:"작게",medium:"보통",large:"크게","x-large":"아주 크게",custom:"사용자 지정"},fontCustomSize:{title:"사용자 지정 글꼴 크기",label:"글꼴 크기",value:"48px"}},nl:{fontsize:"Lettergrootte",fontsizes:{"x-small":"Extra klein",small:"Klein",medium:"Normaal",large:"Groot","x-large":"Extra groot",custom:"Tilpasset"}},pt_br:{fontsize:"Tamanho da fonte",fontsizes:{"x-small":"Extra pequeno",small:"Pequeno",regular:"Médio",large:"Grande","x-large":"Extra grande",custom:"Personalizado"},fontCustomSize:{title:"Tamanho de Fonte Personalizado",label:"Tamanho de Fonte",value:"48px"}},tr:{fontsize:"Yazı Boyutu",fontsizes:{"x-small":"Çok Küçük",small:"Küçük",medium:"Normal",large:"Büyük","x-large":"Çok Büyük",custom:"Görenek"}},zh_tw:{fontsize:"字體大小",fontsizes:{"x-small":"最小",small:"小",medium:"中",large:"大","x-large":"最大",custom:"自訂大小"},fontCustomSize:{title:"自訂義字體大小",label:"字體大小",value:"48px"}}}});var t={sizeList:["x-small","small","medium","large","x-large"],allowCustomSize:!0};function l(t,l){t.$ed.focus(),t.saveRange(),t.execCmd("fontSize","1"),t.$ed.find('font[size="1"]').replaceWith(function(){return e("<span/>",{css:{"font-size":l},html:this.innerHTML})}),e(t.range.startContainer.parentElement).find('span[style=""]').contents().unwrap(),t.restoreRange(),t.syncCode(),t.$c.trigger("tbwchange")}function a(t){var a=[];if(e.each(t.o.plugins.fontsize.sizeList,function(e,s){t.addBtnDef("fontsize_"+s,{text:'<span style="font-size: '+s+';">'+(t.lang.fontsizes[s]||s)+"</span>",hasIcon:!1,fn:function(){l(t,s)}}),a.push("fontsize_"+s)}),t.o.plugins.fontsize.allowCustomSize){var s={fn:function(){t.openModalInsert(t.lang.fontCustomSize.title,{size:{label:t.lang.fontCustomSize.label,value:t.lang.fontCustomSize.value}},function(e){return l(t,e.size),!0})},text:'<span style="font-size: medium;">'+t.lang.fontsizes.custom+"</span>",hasIcon:!1};t.addBtnDef("fontsize_custom",s),a.push("fontsize_custom")}return a}e.extend(!0,e.trumbowyg,{plugins:{fontsize:{init:function(l){l.o.plugins.fontsize=e.extend({},t,l.o.plugins.fontsize||{}),l.addBtnDef("fontsize",{dropdown:a(l)})}}}})}(jQuery);