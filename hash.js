console.log(require('bcryptjs').hashSync(process.argv[2]||'',12))
