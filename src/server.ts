import config from './config'
import { app } from './app'

app().listen(config.port, () => {
	console.info(`Listening on port ${config.port}`)

	console.info(`Here is the bookmarklet code. Make sure you replace <SERVER_ADDRESS> with this server's ip or hostname (including the protocol and port) that your browser can access!`)
	let bookmarklet = `(()=>{window.open("<SERVER_ADDRESS>/block?key=${config.api_key}&url="+encodeURIComponent(location),"_blank","noreferrer,noopener")})()`
	console.info(`\n    javascript:${bookmarklet}\n`)

	console.info(`Then add <SERVER_ADDRESS>/blocklist.txt to your blocking solution of choice.\n`)
})
