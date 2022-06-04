import { Express, Router, Request, Response } from 'express'
import { readFile, writeFile } from 'fs/promises'
import { join } from 'path'

import config from './config'

import noCache from './middleware/no-cache'
import cacheForever from './middleware/cache-forever'

const router = Router()

router.get('/favicon.ico', cacheForever(), (_: Request, res: Response) => res.sendStatus(204))

// router.get('/robots.txt', cacheForever(), (_: Request, res: Response) => {
// 	res.type('text/plain')
// 	res.send('User-agent: *\nDisallow: /')
// })

router.get('/healthcheck', noCache(), (_: Request, res: Response) => {
	res.json({ timestamp: Date.now() })
})


// load blocklist.txt or return an empty array if nonexistent
let readList = (initial: string[] = []) => {
	return new Promise(async (resolve: (blocklist: string[]) => void, reject) => {
		let data
		try {
			data = await readFile(join(config.blocklist_root, 'blocklist.txt'))
		} catch (err){
			if ('code' in (err as any) && (err as any).code !== 'ENOENT'){
				console.error(`Something went wrong while trying to read the blocklist!`)
				console.error(err)
				return reject(err)
			}
		} finally {
			let blocklist: string[] = [...initial]
			// parse file data if it exists
			if (data){
				for (let line of data.toString().split('\n')){
					line = line.trim()
					if (line.length > 0 && line.at(0) != '#' && !blocklist.includes(line)){
						if (config.block_type === 'hostname'){
							line = (new URL(`${line.search(/^[a-z]+:\/\//) === 0 ? '' : 'https://'}${line}`)).hostname
						}
						blocklist.push(line)
					}
				}
			}
			resolve(blocklist)
		}
	})
}

router.get('/block', noCache(), async (req: Request, res: Response) => {
	if (!req.query.key || req.query.key != config.api_key) {
		return res.sendStatus(401) // unauthorized
	}

	if (!req.query.url) {
		console.error('No URL given. Skipping...')
		return res.sendStatus(400) // bad request
	}

	let url = decodeURIComponent(req.query.url as string)
	if (config.block_type === 'hostname'){
		url = (new URL(url)).hostname
	}

	try {
		let blocklist = await readList([url])
		blocklist = blocklist.sort()

		let txt = ''
		for (let line of config.blocklist_header.split('\n')){
			txt += `# ${line}\n`
		}
		txt += '\n'
		for (let entry of blocklist){
			txt += `${entry}\n`
		}

		try {
			await writeFile(join(config.blocklist_root, 'blocklist.txt'), txt)
			console.info(`Blocked ${url}`)
			res.send(`Successfully blocked ${url}`)
		} catch(err){
			console.error(`Something went wrong while trying to write the blocklist!`)
			console.error(err)
			res.sendStatus(500) // internal server error
		}
	} catch(err){
		res.sendStatus(500)
	}
})

router.get('/blocklist.txt', (req: Request, res: Response) => {
	res.sendFile(join(config.blocklist_root, 'blocklist.txt'), {root: join(__dirname, '..')})
})

router.get('/blocklist.hosts.txt', async (req: Request, res: Response) => {
	try {
		let blocklist = await readList()

		let txt = ''
		for (let line of config.blocklist_header.split('\n')){
			txt += `# ${line}\n`
		}
		txt += '\n'
		for (let entry of blocklist){
			txt += `0.0.0.0\t${entry}\n`
		}

		res.send(txt)
	} catch(err){
		res.sendStatus(500)
	}
})

router.get('/blocklist.abp.txt', async (req: Request, res: Response) => {
	try {
		let blocklist = await readList()

		let txt = ''
		for (let line of config.blocklist_header.split('\n')){
			txt += `! ${line}\n`
		}
		txt += '\n'
		for (let entry of blocklist){
			txt += `||${entry}^\n`
		}

		res.send(txt)
	} catch(err){
		res.sendStatus(500)
	}
})

export default router
