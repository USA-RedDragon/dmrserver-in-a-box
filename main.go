package main

import (
	"context"
	"runtime"
	"time"

	"github.com/USA-RedDragon/DMRHub/internal/config"
	"github.com/USA-RedDragon/DMRHub/internal/db"
	"github.com/USA-RedDragon/DMRHub/internal/db/models"
	"github.com/USA-RedDragon/DMRHub/internal/dmr"
	"github.com/USA-RedDragon/DMRHub/internal/http"
	"github.com/USA-RedDragon/DMRHub/internal/repeaterdb"
	"github.com/USA-RedDragon/DMRHub/internal/sdk"
	"github.com/USA-RedDragon/DMRHub/internal/userdb"
	"github.com/go-co-op/gocron"
	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	_ "github.com/tinylib/msgp/printer"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"k8s.io/klog/v2"
)

var scheduler = gocron.NewScheduler(time.UTC)

func initTracer() func(context.Context) error {
	exporter, err := otlptrace.New(
		context.Background(),
		otlptracegrpc.NewClient(
			otlptracegrpc.WithInsecure(),
			otlptracegrpc.WithEndpoint(config.GetConfig().OTLPEndpoint),
		),
	)
	if err != nil {
		klog.Fatal(err)
	}
	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", "DMRHub"),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		klog.Infof("Could not set resources: ", err)
	}

	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resources),
		),
	)
	return exporter.Shutdown
}

func main() {
	defer klog.Flush()

	klog.Infof("DMRHub v%s-%s", sdk.Version, sdk.GitCommit)

	ctx := context.Background()

	if config.GetConfig().OTLPEndpoint != "" {
		cleanup := initTracer()
		defer func() {
			err := cleanup(ctx)
			if err != nil {
				klog.Errorf("Failed to shutdown tracer: %s", err)
			}
		}()
	}

	database := db.MakeDB()

	// Dummy call to get the data decoded into memory early
	go func() {
		repeaterdb.GetDMRRepeaters()
		err := repeaterdb.Update()
		if err != nil {
			klog.Errorf("Failed to update repeater database: %s using built in one", err)
		}
	}()
	_, err := scheduler.Every(1).Day().At("00:00").Do(func() {
		err := repeaterdb.Update()
		if err != nil {
			klog.Errorf("Failed to update repeater database: %s", err)
		}
	})
	if err != nil {
		klog.Errorf("Failed to schedule repeater update: %s", err)
	}

	go func() {
		err = userdb.Update()
		if err != nil {
			klog.Errorf("Failed to update user database: %s using built in one", err)
		}
	}()
	_, err = scheduler.Every(1).Day().At("00:00").Do(func() {
		err = userdb.Update()
		if err != nil {
			klog.Errorf("Failed to update repeater database: %s", err)
		}
	})
	if err != nil {
		klog.Errorf("Failed to schedule user update: %s", err)
	}

	scheduler.StartAsync()

	redis := redis.NewClient(&redis.Options{
		Addr:            config.GetConfig().RedisHost,
		Password:        config.GetConfig().RedisPassword,
		PoolFIFO:        true,
		PoolSize:        runtime.GOMAXPROCS(0) * 10,
		MinIdleConns:    runtime.GOMAXPROCS(0),
		ConnMaxIdleTime: 10 * time.Minute,
	})
	_, err = redis.Ping(ctx).Result()
	if err != nil {
		klog.Errorf("Failed to connect to redis: %s", err)
		return
	}
	defer func() {
		err := redis.Close()
		if err != nil {
			klog.Errorf("Failed to close redis: %s", err)
		}
	}()
	if config.GetConfig().OTLPEndpoint != "" {
		if err := redisotel.InstrumentTracing(redis); err != nil {
			klog.Errorf("Failed to trace redis: %s", err)
			return
		}

		// Enable metrics instrumentation.
		if err := redisotel.InstrumentMetrics(redis); err != nil {
			klog.Errorf("Failed to instrument redis: %s", err)
			return
		}
	}

	dmrServer := dmr.MakeServer(database, redis)
	dmrServer.Listen(ctx)
	defer dmrServer.Stop(ctx)

	// For each repeater in the DB, start a gofunc to listen for calls
	repeaters := models.ListRepeaters(database)
	for _, repeater := range repeaters {
		go repeater.ListenForCalls(ctx, redis)
	}

	http.Start(database, redis)
}
