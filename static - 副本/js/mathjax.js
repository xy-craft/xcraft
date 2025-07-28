// static/js/mathjax.js
window.MathJax = {
  tex: {
    inlineMath: [['$', '$'], ['\\(', '\\)']],
    displayMath: [['$$', '$$'], ['\\[', '\\]']],
    processEscapes: true,
    packages: {'[+]': ['ams', 'boldsymbol', 'physics']},
    tags: 'ams',
    autoload: {
      color: [],
      colorv2: ['color']
    }
  },
  options: {
    enableMenu: true,
    ignoreHtmlClass: 'tex2jax_ignore',
    processHtmlClass: 'tex2jax_process',
    renderActions: {
      addMenu: [0, '', '']
    }
  },
  loader: {
    load: [
      '[tex]/ams',
      '[tex]/boldsymbol',
      '[tex]/physics',
      '[tex]/autoload'
    ],
    paths: {
      tex: 'https://cdn.jsdelivr.net/npm/mathjax@3/es5/input/tex'
    }
  },
  startup: {
    ready: () => {
      // 核心初始化配置
      MathJax.startup.defaultReady();
      
      // 注册类型设置完成后的回调
      MathJax.startup.promise.then(() => {
        console.log('MathJax 初始化完成');
        
        // 自动处理动态内容
        new MutationObserver(() => {
          MathJax.typesetPromise().catch(err => {
            console.log('DOM变化渲染错误:', err);
          });
        }).observe(document.body, {
          childList: true,
          subtree: true
        });
      }).catch(err => {
        console.error('MathJax初始化失败:', err);
      });
    }
  },
  // 自定义错误处理
  typesetError: (error) => {
    console.warn('公式渲染错误:', error);
    return MathJax.typesetClear()
      .then(() => MathJax.typesetPromise());
  }
};

// 自动重试机制
MathJax.typesetPromise = function() {
  return MathJax.typeset()
    .catch(MathJax.typesetError)
    .then(() => MathJax.typeset());
};