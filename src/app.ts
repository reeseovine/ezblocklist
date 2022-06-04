import express, { NextFunction, Request, Response, Express } from 'express'
import 'express-async-errors'

import routes from './routes'

export const app = (app = express()): Express => {
	app.use(routes)

	app.use((_, response) => response.sendStatus(404))
	app.use((error: Error, _: Request, __: Response, next: NextFunction) => {
		console.error(error)
		next(error)
	})

	return app
}
