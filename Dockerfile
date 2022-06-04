FROM node:lts-alpine AS builder
ENV NODE_ENV development

WORKDIR /app
COPY . .

# Install dependencies and transpile typescript
RUN npm ci && \
	npm run build



FROM node:lts-alpine AS runner
ENV NODE_ENV production

# Copy source code
WORKDIR /app
COPY package* ./
COPY --from=builder /app/dist ./dist

# Install dependencies
RUN npm ci --omit=dev

# Create volume to persist database even if you forget to map a volume
VOLUME /data

# Start!
CMD npm start
