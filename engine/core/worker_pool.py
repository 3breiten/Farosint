#!/usr/bin/env python3
"""
FAROSINT Worker Pool - VERSIÓN CORREGIDA
Gestiona ejecución paralela de herramientas OSINT
"""

import threading
import queue
import time
import sys
from enum import Enum
from datetime import datetime

class TaskStatus(Enum):
    """Estados posibles de una tarea"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

class Task:
    """Representa una tarea OSINT"""
    
    def __init__(self, task_id, name, function, args=None, kwargs=None,
                 timeout=600, priority=3):
        """
        Crear nueva tarea
        
        Args:
            task_id: Identificador único
            name: Nombre de la tarea
            function: Función a ejecutar
            args: Argumentos posicionales
            kwargs: Argumentos con nombre
            timeout: Timeout en segundos
            priority: Prioridad (1=máxima, 5=mínima)
        """
        self.task_id = task_id
        self.name = name
        self.function = function
        self.args = args or []
        self.kwargs = kwargs or {}
        self.timeout = timeout
        self.priority = priority
        
        self.status = TaskStatus.PENDING
        self.result = None
        self.error = None
        self.start_time = None
        self.end_time = None
    
    def __lt__(self, other):
        """Comparación para cola de prioridad"""
        return self.priority < other.priority
    
    def get_duration(self):
        """Obtener duración de ejecución"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

class Worker(threading.Thread):
    """Worker que procesa tareas"""
    
    def __init__(self, worker_id, task_queue, results, lock):
        """
        Inicializar worker
        
        Args:
            worker_id: ID del worker
            task_queue: Cola de tareas compartida
            results: Diccionario de resultados compartido
            lock: Lock para sincronización
        """
        super().__init__()
        self.worker_id = worker_id
        self.task_queue = task_queue
        self.results = results
        self.lock = lock
        self.daemon = True
        self.running = True
    
    def run(self):
        """Ejecutar worker"""
        while self.running:
            try:
                # Obtener tarea (timeout 1 segundo)
                task = self.task_queue.get(timeout=1)
                
                if task is None:  # Señal de parada
                    break
                
                # Ejecutar tarea
                self._execute_task(task)
                
                # Marcar como completada
                self.task_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"[Worker {self.worker_id}] Error: {e}")
    
    def _execute_task(self, task):
        """
        Ejecutar una tarea con timeout
        
        Args:
            task: Tarea a ejecutar
        """
        task.status = TaskStatus.RUNNING
        task.start_time = datetime.now()
        
        print(f"[Worker {self.worker_id}] Ejecutando: {task.name}")
        
        # Timer para timeout
        timer = threading.Timer(task.timeout, self._timeout_handler, [task])
        timer.start()
        
        try:
            # Ejecutar función
            result = task.function(*task.args, **task.kwargs)
            
            # Cancelar timer si terminó antes
            timer.cancel()
            
            # Guardar resultado
            task.result = result
            task.status = TaskStatus.COMPLETED
            print(f"[Worker {self.worker_id}] ✓ Completado: {task.name}")
            
        except Exception as e:
            timer.cancel()
            task.error = str(e)
            task.status = TaskStatus.FAILED
            print(f"[Worker {self.worker_id}] ✗ Error en {task.name}: {e}")
            
        finally:
            task.end_time = datetime.now()
            
            # Guardar resultado en diccionario compartido
            with self.lock:
                self.results[task.task_id] = task
    
    def _timeout_handler(self, task):
        """Manejar timeout de tarea"""
        task.status = TaskStatus.TIMEOUT
        task.end_time = datetime.now()
        print(f"[Worker {self.worker_id}] ⏱ Timeout: {task.name} ({task.timeout}s)")
    
    def stop(self):
        """Detener worker"""
        self.running = False

class WorkerPool:
    """Pool de workers para ejecución paralela"""
    
    def __init__(self, max_workers=4):
        """
        Inicializar pool
        
        Args:
            max_workers: Número máximo de workers
        """
        self.max_workers = max_workers
        self.task_queue = queue.Queue()
        self.results = {}
        self.lock = threading.Lock()
        self.workers = []
        self.task_counter = 0
        
        # Iniciar workers
        self._start_workers()
        
        # REMOVIDO: signal.signal() porque no funciona en threads secundarios
        # Los signals solo funcionan en el main thread
    
    def _start_workers(self):
        """Iniciar workers"""
        for i in range(self.max_workers):
            worker = Worker(i, self.task_queue, self.results, self.lock)
            worker.start()
            self.workers.append(worker)
        print(f"[Pool] {self.max_workers} workers iniciados")
    
    def submit(self, name, function, args=None, kwargs=None, 
               timeout=600, priority=3):
        """
        Enviar tarea al pool
        
        Args:
            name: Nombre de la tarea
            function: Función a ejecutar
            args: Argumentos posicionales
            kwargs: Argumentos con nombre
            timeout: Timeout en segundos
            priority: Prioridad (1=máxima, 5=mínima)
            
        Returns:
            task_id de la tarea enviada
        """
        self.task_counter += 1
        task_id = f"task_{self.task_counter}"
        
        task = Task(
            task_id=task_id,
            name=name,
            function=function,
            args=args,
            kwargs=kwargs,
            timeout=timeout,
            priority=priority
        )
        
        # Agregar a cola
        self.task_queue.put(task)
        print(f"[Pool] Tarea encolada: {name} (prioridad: {priority})")
        
        return task_id
    
    def wait_all(self):
        """Esperar a que todas las tareas terminen"""
        print("[Pool] Esperando a que terminen todas las tareas...")
        self.task_queue.join()
        print("[Pool] Todas las tareas completadas")
    
    def get_result(self, task_id):
        """
        Obtener resultado de una tarea
        
        Args:
            task_id: ID de la tarea
            
        Returns:
            Task object con resultado
        """
        with self.lock:
            return self.results.get(task_id)
    
    def get_all_results(self):
        """Obtener todos los resultados"""
        with self.lock:
            return dict(self.results)
    
    def get_stats(self):
        """Obtener estadísticas del pool"""
        with self.lock:
            total = len(self.results)
            by_status = {}
            
            for task in self.results.values():
                status = task.status.value
                by_status[status] = by_status.get(status, 0) + 1
            
            durations = [
                task.get_duration() 
                for task in self.results.values() 
                if task.get_duration() is not None
            ]
            avg_duration = sum(durations) / len(durations) if durations else 0
            
            return {
                'total_tasks': total,
                'by_status': by_status,
                'average_duration': avg_duration,
                'workers': self.max_workers
            }
    
    def shutdown(self):
        """Cerrar pool de workers"""
        print("[Pool] Cerrando workers...")
        
        # Enviar señal de parada a cada worker
        for _ in self.workers:
            self.task_queue.put(None)
        
        # Esperar a que terminen
        for worker in self.workers:
            worker.join(timeout=5)
        
        print("[Pool] Pool cerrado")
