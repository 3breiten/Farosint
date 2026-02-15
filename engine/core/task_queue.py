#!/usr/bin/env python3
"""
FAROSINT Task Queue Manager
Gestiona cola de tareas con prioridades y dependencias
"""

import threading
from collections import defaultdict
from datetime import datetime
from enum import Enum

class TaskDependency:
    """Define dependencias entre tareas"""
    
    def __init__(self):
        self.dependencies = defaultdict(set)  # task_id -> set of dependency task_ids
        self.dependents = defaultdict(set)    # task_id -> set of dependent task_ids
    
    def add_dependency(self, task_id, depends_on):
        """
        Agregar dependencia
        
        Args:
            task_id: ID de la tarea
            depends_on: ID de la tarea de la que depende
        """
        self.dependencies[task_id].add(depends_on)
        self.dependents[depends_on].add(task_id)
    
    def get_dependencies(self, task_id):
        """Obtener dependencias de una tarea"""
        return self.dependencies.get(task_id, set())
    
    def get_dependents(self, task_id):
        """Obtener tareas que dependen de esta"""
        return self.dependents.get(task_id, set())
    
    def can_run(self, task_id, completed_tasks):
        """
        Verificar si una tarea puede ejecutarse
        
        Args:
            task_id: ID de la tarea
            completed_tasks: Set de tareas completadas
            
        Returns:
            True si todas sus dependencias están completadas
        """
        dependencies = self.get_dependencies(task_id)
        return dependencies.issubset(completed_tasks)

class TaskQueueManager:
    """Gestor de cola de tareas con prioridades"""
    
    def __init__(self):
        self.tasks = {}              # task_id -> task_info
        self.dependency_graph = TaskDependency()
        self.completed_tasks = set()
        self.failed_tasks = set()
        self.running_tasks = set()
        self.lock = threading.Lock()
    
    def add_task(self, task_id, name, priority=3, depends_on=None):
        """
        Agregar tarea a la cola
        
        Args:
            task_id: ID único de la tarea
            name: Nombre de la tarea
            priority: Prioridad (1=máxima, 5=mínima)
            depends_on: Lista de task_ids de los que depende
        """
        with self.lock:
            self.tasks[task_id] = {
                'task_id': task_id,
                'name': name,
                'priority': priority,
                'added_at': datetime.now(),
                'started_at': None,
                'completed_at': None,
                'status': 'pending'
            }
            
            # Agregar dependencias
            if depends_on:
                for dep_id in depends_on:
                    self.dependency_graph.add_dependency(task_id, dep_id)
    
    def get_next_task(self):
        """
        Obtener siguiente tarea ejecutable (sin dependencias pendientes)
        
        Returns:
            task_id de la siguiente tarea o None
        """
        with self.lock:
            # Filtrar tareas que pueden ejecutarse
            runnable = []
            
            for task_id, task_info in self.tasks.items():
                if task_info['status'] != 'pending':
                    continue
                
                if task_id in self.running_tasks:
                    continue
                
                # Verificar dependencias
                if self.dependency_graph.can_run(task_id, self.completed_tasks):
                    runnable.append((task_info['priority'], task_id, task_info))
            
            if not runnable:
                return None
            
            # Ordenar por prioridad (menor número = mayor prioridad)
            runnable.sort(key=lambda x: x[0])
            
            # Retornar tarea con mayor prioridad
            _, task_id, _ = runnable[0]
            return task_id
    
    def mark_running(self, task_id):
        """Marcar tarea como en ejecución"""
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]['status'] = 'running'
                self.tasks[task_id]['started_at'] = datetime.now()
                self.running_tasks.add(task_id)
    
    def mark_completed(self, task_id, success=True):
        """
        Marcar tarea como completada
        
        Args:
            task_id: ID de la tarea
            success: True si completó exitosamente
        """
        with self.lock:
            if task_id in self.tasks:
                self.tasks[task_id]['status'] = 'completed' if success else 'failed'
                self.tasks[task_id]['completed_at'] = datetime.now()
                
                if task_id in self.running_tasks:
                    self.running_tasks.remove(task_id)
                
                if success:
                    self.completed_tasks.add(task_id)
                else:
                    self.failed_tasks.add(task_id)
    
    def get_progress(self):
        """
        Obtener progreso actual
        
        Returns:
            Dict con estadísticas de progreso
        """
        with self.lock:
            total = len(self.tasks)
            completed = len(self.completed_tasks)
            failed = len(self.failed_tasks)
            running = len(self.running_tasks)
            pending = total - completed - failed - running
            
            return {
                'total': total,
                'completed': completed,
                'failed': failed,
                'running': running,
                'pending': pending,
                'progress_percent': (completed / total * 100) if total > 0 else 0
            }
    
    def get_task_info(self, task_id):
        """Obtener información de una tarea"""
        with self.lock:
            return self.tasks.get(task_id)
    
    def get_all_tasks(self):
        """Obtener todas las tareas"""
        with self.lock:
            return dict(self.tasks)

# Ejemplo de uso
if __name__ == "__main__":
    queue = TaskQueueManager()
    
    # Agregar tareas con dependencias
    # Fase 1: Recolección (sin dependencias, alta prioridad)
    queue.add_task('subfinder', 'Subfinder', priority=1)
    queue.add_task('shodan', 'Shodan', priority=1)
    
    # Fase 2: Depende de Fase 1
    queue.add_task('httpx', 'Httpx', priority=3, depends_on=['subfinder'])
    
    # Fase 3: Depende de Fase 2
    queue.add_task('nmap', 'Nmap', priority=4, depends_on=['httpx'])
    queue.add_task('whatweb', 'WhatWeb', priority=4, depends_on=['httpx'])
    
    # Fase 4: Depende de Fase 3
    queue.add_task('nuclei', 'Nuclei', priority=5, depends_on=['whatweb'])
    
    # Simular ejecución
    print("=== SIMULACIÓN DE EJECUCIÓN ===\n")
    
    while True:
        next_task = queue.get_next_task()
        
        if next_task is None:
            progress = queue.get_progress()
            if progress['pending'] == 0 and progress['running'] == 0:
                break
            continue
        
        task_info = queue.get_task_info(next_task)
        print(f"Ejecutando: {task_info['name']} (prioridad: {task_info['priority']})")
        
        queue.mark_running(next_task)
        
        # Simular ejecución
        import time
        time.sleep(1)
        
        queue.mark_completed(next_task, success=True)
        
        # Mostrar progreso
        progress = queue.get_progress()
        print(f"  Progreso: {progress['completed']}/{progress['total']} ({progress['progress_percent']:.1f}%)\n")
    
    print("=== FINALIZADO ===")
    final_progress = queue.get_progress()
    print(f"Completadas: {final_progress['completed']}")
    print(f"Fallidas: {final_progress['failed']}")
